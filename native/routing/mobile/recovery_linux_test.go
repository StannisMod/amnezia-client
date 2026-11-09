//go:build linux && with_gvisor

package mobile

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/StannisMod/amnezia-client/native/routing/wireguard"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

// The actual mobile Session, native packet FD and encrypted transport stay alive
// while the protected UDP endpoint, DNS generation and source port are replaced.
// This is not an Android radio/battery test; the APK host is tested separately.
func TestMobileRecoveryKeepsInteractiveAndDelayedMediaTCP(t *testing.T) {
	for _, kind := range []string{"awg", "wireguard"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			key := func() (*ecdh.PrivateKey, string) {
				k, e := ecdh.X25519().GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				return k, base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
			}
			a, _ := key()
			b, bPub := key()
			params := map[string]string(nil)
			if kind == "awg" {
				params = map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
			}
			serverTun, serverNet, e := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1280)
			if e != nil {
				t.Fatal(e)
			}
			ipc := "private_key=" + hex.EncodeToString(b.Bytes()) + "\nlisten_port=0\n"
			for k, v := range params {
				ipc += k + "=" + v + "\n"
			}
			ipc += "replace_peers=true\npublic_key=" + hex.EncodeToString(a.PublicKey().Bytes()) + "\nallowed_ip=10.77.0.1/32\n"
			peer, e := awg.NewConfiguredDevice(serverTun, conn.NewStdNetBind(), ipc)
			if e != nil {
				serverTun.Close()
				t.Fatal(e)
			}
			defer peer.Close()
			state, e := peer.IpcGet()
			if e != nil {
				t.Fatal(e)
			}
			var port uint16
			for _, line := range strings.Split(state, "\n") {
				if strings.HasPrefix(line, "listen_port=") {
					n, e := strconv.Atoi(strings.TrimPrefix(line, "listen_port="))
					if e != nil {
						t.Fatal(e)
					}
					port = uint16(n)
				}
			}
			if port == 0 {
				t.Fatal("peer has no UDP listener")
			}
			peerAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
			front := func() (netip.AddrPort, func()) {
				socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					t.Fatal(e)
				}
				go func() {
					var client *net.UDPAddr
					buf := make([]byte, 65535)
					for {
						n, from, e := socket.ReadFromUDP(buf)
						if e != nil {
							return
						}
						if from.String() == peerAddr.String() {
							if client != nil {
								socket.WriteToUDP(buf[:n], client)
							}
						} else {
							client = from
							socket.WriteToUDP(buf[:n], peerAddr)
						}
					}
				}()
				return socket.LocalAddr().(*net.UDPAddr).AddrPort(), func() { socket.Close() }
			}
			endpoint, closeFirst := front()
			defer closeFirst()
			listen, e := serverNet.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.2:18443"))
			if e != nil {
				t.Fatal(e)
			}
			defer listen.Close()
			var accepts atomic.Int32
			go func() {
				for {
					c, e := listen.Accept()
					if e != nil {
						return
					}
					accepts.Add(1)
					go func() { defer c.Close(); io.Copy(c, c) }()
				}
			}()
			pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if e != nil {
				t.Fatal(e)
			}
			unix.SetNonblock(pair[1], true)
			file := os.NewFile(uintptr(pair[1]), "mobile-app-packets")
			packets, e := net.FileConn(file)
			file.Close()
			if e != nil {
				unix.Close(pair[0])
				t.Fatal(e)
			}
			defer packets.Close()
			var deny atomic.Bool
			var released, protected atomic.Int32
			platform, e := New(pair[0], Hooks{Protect: func(fd int) error {
				if deny.Load() {
					return fmt.Errorf("replacement network unavailable")
				}
				protected.Add(1)
				return nil
			}, Release: func() { released.Add(1) }, Interfaces: func() ([]adapter.NetworkInterface, error) {
				return []adapter.NetworkInterface{{Interface: control.Interface{Index: 1, Name: "lo", MTU: 65536, Flags: net.FlagUp | net.FlagLoopback, Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}}}, nil
			}})
			if e != nil {
				unix.Close(pair[0])
				t.Fatal(e)
			}
			config := awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: base64.StdEncoding.EncodeToString(a.Bytes()), PublicKey: bPub, Endpoint: endpoint, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Parameters: params}
			sessionConfig := engine.SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: config, Resolver: netip.MustParseAddrPort("10.77.0.2:53"), ResolverAction: rules.VPN}
			if kind == "wireguard" {
				sessionConfig.AWG = awg.Config{}
				sessionConfig.VPN = &engine.TransportConfig{Type: kind, WireGuard: &wireguard.Config{Address: config.Address, PrivateKey: config.PrivateKey, PublicKey: config.PublicKey, Endpoint: config.Endpoint, AllowedIPs: config.AllowedIPs}}
			}
			raw, _ := json.Marshal(sessionConfig)
			session, e := StartWithNetworkDNS(ctx, platform, raw)
			if e != nil {
				t.Fatal(e)
			}
			defer session.Close()
			appTun, appStack, e := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("172.19.0.1")}, 1280)
			if e != nil {
				t.Fatal(e)
			}
			defer appTun.Close()
			go func() {
				buf := make([]byte, 65535)
				sizes := make([]int, 1)
				for {
					_, e := appTun.Read([][]byte{buf}, sizes, 0)
					if e != nil {
						return
					}
					if _, e = packets.Write(buf[:sizes[0]]); e != nil {
						return
					}
				}
			}()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, e := packets.Read(buf)
					if e != nil {
						return
					}
					if _, e = appTun.Write([][]byte{buf[:n]}, 0); e != nil {
						return
					}
				}
			}()
			dial := func() net.Conn {
				c, e := appStack.DialContext(ctx, "tcp", "10.77.0.2:18443")
				if e != nil {
					t.Fatal(e)
				}
				c.SetDeadline(time.Now().Add(20 * time.Second))
				return c
			}
			exchange := func(c net.Conn, payload []byte) {
				t.Helper()
				if _, e := c.Write(payload); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, len(payload))
				if _, e := io.ReadFull(c, got); e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("corrupt original TCP stream")
				}
			}
			interactive := dial()
			defer interactive.Close()
			for i := 0; i < 10; i++ {
				exchange(interactive, []byte(fmt.Sprintf("message-%d", i)))
				if e := session.ProbeUnderlay(); e != nil {
					t.Fatal(e)
				}
				if e := session.ReloadNetworkDNS(dnspolicy.NetworkSnapshot{}); e != nil {
					t.Fatal(e)
				}
			}
			// Start a distinct large media flow after an established interactive session.
			media := dial()
			defer media.Close()
			payload := make([]byte, 256<<10)
			rand.Read(payload)
			exchange(media, payload)
			replacement, closeReplacement := front()
			defer closeReplacement()
			closeFirst()
			deny.Store(true)
			if e := session.RefreshUnderlay(replacement); e == nil {
				t.Fatal("failed socket protection was accepted")
			}
			if released.Load() != 0 {
				t.Fatal("failed recovery destroyed mobile owner")
			}
			deny.Store(false)
			if e := session.RefreshUnderlay(replacement); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 3; i++ {
				exchange(interactive, []byte(fmt.Sprintf("after-handover-%d", i)))
				exchange(media, payload)
				if e := session.ReloadNetworkDNS(dnspolicy.NetworkSnapshot{}); e != nil {
					t.Fatal(e)
				}
			}
			if accepts.Load() != 2 {
				t.Fatalf("replacement TCP connections concealed outage: %d", accepts.Load())
			}
			if released.Load() != 0 || protected.Load() < 2 {
				t.Fatalf("owner/protection released=%d protected=%d", released.Load(), protected.Load())
			}
			if e := session.Close(); e != nil {
				t.Fatal(e)
			}
			if released.Load() != 1 {
				t.Fatal("explicit stop did not release host exactly once")
			}
			if e := session.RefreshUnderlay(replacement); e == nil {
				t.Fatal("closed session revived")
			}
		})
	}
}
