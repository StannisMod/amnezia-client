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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/StannisMod/amnezia-client/native/routing/wireguard"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

type recoveryWriteGate struct{ entered, resume chan struct{} }
type recoveryPacketLink struct {
	net.Conn
	gate        atomic.Pointer[recoveryWriteGate]
	writeErrors atomic.Uint32
}

func (link *recoveryPacketLink) Write(packet []byte) (int, error) {
	if gate := link.gate.Swap(nil); gate != nil {
		close(gate.entered)
		<-gate.resume
	}
	n, err := link.Conn.Write(packet)
	if err != nil {
		link.writeErrors.Add(1)
	}
	return n, err
}

// The actual mobile Session, native packet FD and encrypted transport stay alive
// while the protected UDP endpoint, DNS generation and source port are replaced.
// This is not an Android radio/battery test; the APK host is tested separately.
func TestMobileRecoveryKeepsInteractiveAndDelayedMediaTCP(t *testing.T) {
	for _, kind := range []string{"awg", "wireguard"} {
		for _, appIPv6 := range []bool{false, true} {
			for _, vpnIPv6 := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/appIPv6=%v/vpnIPv6=%v", kind, appIPv6, vpnIPv6), func(t *testing.T) {
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
					clientIP, serverIP := "10.77.0.1", "10.77.0.2"
					prefix := "10.77.0.1/32"
					if vpnIPv6 {
						clientIP, serverIP, prefix = "fd77::1", "fd77::2", "fd77::1/128"
					}
					serverTun, serverNet, e := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr(serverIP)}, 1280)
					if e != nil {
						t.Fatal(e)
					}
					ipc := "private_key=" + hex.EncodeToString(b.Bytes()) + "\nlisten_port=0\n"
					for k, v := range params {
						ipc += k + "=" + v + "\n"
					}
					ipc += "replace_peers=true\npublic_key=" + hex.EncodeToString(a.PublicKey().Bytes()) + "\nallowed_ip=" + prefix + "\n"
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
					listen, e := serverNet.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 18443))
					if e != nil {
						t.Fatal(e)
					}
					defer listen.Close()
					resolver, e := serverNet.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 53))
					if e != nil {
						t.Fatal(e)
					}
					defer resolver.Close()
					go func() {
						buf := make([]byte, 4096)
						for {
							n, from, e := resolver.ReadFrom(buf)
							if e != nil {
								return
							}
							var query dns.Msg
							if query.Unpack(buf[:n]) != nil {
								continue
							}
							var reply dns.Msg
							reply.SetReply(&query)
							if len(query.Question) > 0 {
								q := query.Question[0]
								if q.Qtype == dns.TypeA && !vpnIPv6 {
									reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(serverIP).To4()}}
								}
								if q.Qtype == dns.TypeAAAA && vpnIPv6 {
									reply.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1}, AAAA: net.ParseIP(serverIP)}}
								}
							}
							raw, _ := reply.Pack()
							resolver.WriteTo(raw, from)
						}
					}()

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
					var appLink atomic.Pointer[recoveryPacketLink]
					appLink.Store(&recoveryPacketLink{Conn: packets})
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
					config := awg.Config{Address: []netip.Addr{netip.MustParseAddr(clientIP)}, PrivateKey: base64.StdEncoding.EncodeToString(a.Bytes()), PublicKey: bPub, Endpoint: endpoint, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, Parameters: params}
					sessionConfig := engine.SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: config, Resolver: netip.AddrPortFrom(netip.MustParseAddr(serverIP), 53), ResolverAction: rules.VPN}
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
					appTun, appStack, e := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("fdfe:dcba:9876::1")}, 1280)
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
							link := appLink.Load()
							if _, e = link.Write(buf[:sizes[0]]); e != nil {
								// A packet already selected for the retired capture can
								// be lost. Keep forwarding later stack retransmissions.
								// Failure of the current capture must still stop output.
								if appLink.Load() != link {
									continue
								}
								return
							}
						}
					}()
					pumpInput := func(link net.Conn) {
						go func() {
							buf := make([]byte, 65535)
							for {
								n, e := link.Read(buf)
								if e != nil {
									return
								}
								if _, e = appTun.Write([][]byte{buf[:n]}, 0); e != nil {
									return
								}
							}
						}()
					}
					pumpInput(packets)
					// The virtual application family is independent of the real
					// origin and inner VPN family. Both directions must work.
					query, e := appStack.DialContext(ctx, "udp", "172.19.0.2:53")
					if e != nil {
						t.Fatal(e)
					}
					query.SetDeadline(time.Now().Add(3 * time.Second))
					kind := uint16(dns.TypeA)
					if appIPv6 {
						kind = dns.TypeAAAA
					}
					var request dns.Msg
					request.SetQuestion("media.test.", kind)
					raw, _ = request.Pack()
					if _, e = query.Write(raw); e != nil {
						t.Fatal(e)
					}
					buffer := make([]byte, 4096)
					n, e := query.Read(buffer)
					query.Close()
					if e != nil {
						t.Fatal(e)
					}
					var answer dns.Msg
					if e = answer.Unpack(buffer[:n]); e != nil {
						t.Fatal(e)
					}
					if len(answer.Answer) != 1 {
						t.Fatalf("missing managed DNS response: %v", answer)
					}
					var fake string
					if appIPv6 {
						fake = answer.Answer[0].(*dns.AAAA).AAAA.String()
					} else {
						fake = answer.Answer[0].(*dns.A).A.String()
					}
					rangeIP := "198.18.0.0/15"
					if appIPv6 {
						rangeIP = "fc00::/18"
					}
					if !netip.MustParsePrefix(rangeIP).Contains(netip.MustParseAddr(fake)) {
						t.Fatal("not a managed FakeIP")
					}
					target := net.JoinHostPort(fake, "18443")
					dial := func() net.Conn {
						c, e := appStack.DialContext(ctx, "tcp", target)
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
					if !vpnIPv6 {
						// A real IPv6 destination is different from a virtual
						// IPv6 FakeIP with an IPv4 origin. Report it promptly
						// without leaking to native egress or killing the old
						// interactive TCP connection.
						nativeBefore := protected.Load()
						unavailable, err := appStack.DialContext(ctx, "tcp", "[2001:db8:dead::2]:18443")
						if err == nil {
							unavailable.SetReadDeadline(time.Now().Add(2 * time.Second))
							var one [1]byte
							_, err = unavailable.Read(one[:])
							unavailable.Close()
						}
						if err == nil {
							t.Fatal("IPv4-only VPN accepted an unavailable real IPv6 origin")
						}
						if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
							t.Fatal("unavailable IPv6 stalled instead of failing promptly")
						}
						if protected.Load() != nativeBefore {
							t.Fatal("unavailable IPv6 attempted native bypass")
						}
						exchange(interactive, []byte("interactive-still-alive-after-ipv6-failure"))
					}
					// Start a distinct large media flow after an established interactive session.
					media := dial()
					defer media.Close()
					// Replace the native capture while both original TCP
					// connections remain in the same application/core stacks.
					beforeCore := session.core
					descriptor := platform.capture.(*packetDescriptor)
					for i := 0; i < 2; i++ {
						old := appLink.Load()
						resume := func() {}
						var queued chan error
						pending := []byte("original-stream-packet-at-capture-retirement")
						if i == 0 {
							gate := &recoveryWriteGate{entered: make(chan struct{}), resume: make(chan struct{})}
							resume = sync.OnceFunc(func() { close(gate.resume) })
							defer resume()
							old.gate.Store(gate)
							queued = make(chan error, 1)
							go func() { _, err := interactive.Write(pending); queued <- err }()
							select {
							case <-gate.entered:
							case <-time.After(3 * time.Second):
								t.Fatal("application output did not reach retirement gate")
							}
						}
						next, newApp := capturePair(t)
						appLink.Store(&recoveryPacketLink{Conn: newApp})
						if i == 0 {
							descriptor.file.Close()
							<-descriptor.done
							if platform.CaptureError() == nil {
								t.Fatal("retired reader was reported healthy before handover")
							}
						}
						if err := session.ReplaceCapture(next); err != nil {
							t.Fatal(err)
						}
						pumpInput(newApp)
						old.Close()
						resume()
						if queued != nil {
							if err := <-queued; err != nil {
								t.Fatal(err)
							}
							received := make([]byte, len(pending))
							if _, err := io.ReadFull(interactive, received); err != nil {
								t.Fatalf("packet queued before capture retirement: %v", err)
							}
							if !bytes.Equal(received, pending) {
								t.Fatal("queued original TCP stream corrupted")
							}
							if old.writeErrors.Load() == 0 {
								t.Fatal("retired capture write error was not exercised")
							}
						}
						exchange(interactive, []byte("interactive-after-capture-handover"))
						exchange(media, []byte("media-after-capture-handover"))
						if session.core != beforeCore || platform.capture != descriptor || released.Load() != 0 {
							t.Fatal("capture handover replaced the TCP core")
						}
					}

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
	}
}
