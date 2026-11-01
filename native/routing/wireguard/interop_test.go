package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	at "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wt "golang.zx2c4.com/wireguard/tun"
)

// Only the private packet stack is shared. The reference peer's crypto,
// handshake and UDP bind are the independent, pinned upstream wireguard-go.
// Hide only the optional host route-listener extension: loopback tests need
// neither native route monitoring nor privileged netlink sockets.
type referenceBind struct{ conn.Bind }

type referenceTUN struct {
	at.Device
	events chan wt.Event
	once   sync.Once
}

func (t *referenceTUN) Events() <-chan wt.Event { return t.events }
func (t *referenceTUN) Close() error {
	var err error
	t.once.Do(func() { err = t.Device.Close(); close(t.events) })
	return err
}

func TestStandardWireGuardInteroperability(t *testing.T) {
	for _, addresses := range [][2]string{{"10.88.0.1", "10.88.0.2"}, {"fd88::1", "fd88::2"}} {
		t.Run(addresses[0], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, _ := ecdh.X25519().GenerateKey(rand.Reader)
			server, _ := ecdh.X25519().GenerateKey(rand.Reader)
			packet, stack, err := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr(addresses[1])}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			peer := device.NewDevice(&referenceTUN{Device: packet, events: make(chan wt.Event)}, referenceBind{conn.NewStdNetBind()}, device.NewLogger(device.LogLevelSilent, ""))
			defer peer.Close()
			prefix := "/32"
			if strings.Contains(addresses[0], ":") {
				prefix = "/128"
			}
			if err = peer.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=%s%s\n", hex.EncodeToString(server.Bytes()), hex.EncodeToString(client.PublicKey().Bytes()), addresses[0], prefix)); err != nil {
				t.Fatal(err)
			}
			if err = peer.Up(); err != nil {
				t.Fatal(err)
			}
			state, err := peer.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			var port uint64
			for _, line := range strings.Split(state, "\n") {
				if value, ok := strings.CutPrefix(line, "listen_port="); ok {
					port, _ = strconv.ParseUint(value, 10, 16)
				}
			}
			if port == 0 {
				t.Fatal("reference peer did not bind")
			}
			c := Config{Address: []netip.Addr{netip.MustParseAddr(addresses[0])}, PrivateKey: base64.StdEncoding.EncodeToString(client.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(addresses[1] + prefix)}}
			if err = c.Validate(); err != nil {
				t.Fatal(err)
			}
			var lc net.ListenConfig
			transport, err := awg.New(ctx, c.Native(), lc.ListenPacket)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			address := netip.AddrPortFrom(netip.MustParseAddr(addresses[1]), 19081)
			tcp, err := stack.ListenTCPAddrPort(address)
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			go func() {
				client, err := tcp.Accept()
				if err != nil {
					return
				}
				defer client.Close()
				io.Copy(client, io.LimitReader(client, 4))
			}()
			stream, err := transport.DialContext(ctx, "tcp", address.String())
			if err != nil {
				t.Fatal(err)
			}
			stream.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = stream.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 4)
			if _, err = io.ReadFull(stream, response); err != nil || string(response) != "ping" {
				t.Fatal("TCP interoperability", err)
			}
			stream.Close()
			udp, err := stack.ListenUDPAddrPort(address)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				buffer := make([]byte, 128)
				n, a, err := udp.ReadFrom(buffer)
				if err == nil {
					udp.WriteTo(buffer[:n], a)
				}
			}()
			datagram, err := transport.DialContext(ctx, "udp", address.String())
			if err != nil {
				t.Fatal(err)
			}
			defer datagram.Close()
			datagram.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = datagram.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadFull(datagram, response); err != nil || string(response) != "ping" {
				t.Fatal("UDP interoperability", err)
			}
			stats, err := transport.Stats()
			if err != nil || stats.LastHandshake == 0 {
				t.Fatal("handshake statistics missing", err)
			}
		})
	}
}
