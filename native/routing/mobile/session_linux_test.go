//go:build linux && with_gvisor

package mobile

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func sampleConfig(t *testing.T) []byte {
	t.Helper()
	a, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	b, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(engine.SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: awg.Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: base64.StdEncoding.EncodeToString(a.Bytes()), PublicKey: base64.StdEncoding.EncodeToString(b.PublicKey().Bytes()), Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, Resolver: netip.MustParseAddrPort("1.1.1.1:53"), ResolverAction: rules.VPN})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Use a datagram FD as a packet source, exercising NativeTun and its real
// gVisor FD endpoint without claiming an Android VpnService/device test.
func TestOwnedPacketFDManagedDNSAndCleanup(t *testing.T) {
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	unix.SetNonblock(pair[1], true)
	appFile := os.NewFile(uintptr(pair[1]), "app-packets")
	app, e := net.FileConn(appFile)
	appFile.Close()
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	var released, protected atomic.Int32
	hooks := Hooks{Protect: func(fd int) error {
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e != nil {
			return e
		}
		protected.Add(1)
		return nil
	}, Interfaces: func() ([]adapter.NetworkInterface, error) {
		return []adapter.NetworkInterface{{Interface: control.Interface{Index: 1, Name: "lo", MTU: 65536, Flags: net.FlagUp | net.FlagLoopback, Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}}}, nil
	}, Release: func() { released.Add(1) }}
	platform, e := New(pair[0], hooks)
	if e != nil {
		unix.Close(pair[0])
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, e := Start(ctx, platform, sampleConfig(t))
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	if _, e = platform.OpenInterface(&tun.Options{}, option.TunPlatformOptions{}); e == nil {
		t.Fatal("second packet reader was accepted")
	}
	packet := dnsPacket(t)
	app.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = app.Write(packet); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 4096)
	n, e := app.Read(reply)
	if e != nil {
		t.Fatal(e)
	}
	var answer dns.Msg
	if n < 28 {
		t.Fatal("truncated DNS packet")
	}
	if e = answer.Unpack(reply[28:n]); e != nil {
		t.Fatal(e)
	}
	if len(answer.Answer) != 1 {
		t.Fatal("missing managed DNS response")
	}
	fake := answer.Answer[0].(*dns.A).A.String()
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(netip.MustParseAddr(fake)) {
		t.Fatal("DNS response was not a FakeIP")
	}
	session.Close()
	session.Close()
	if _, e = unix.FcntlInt(uintptr(pair[0]), unix.F_GETFD, 0); e != unix.EBADF {
		t.Fatal("capture FD survived shutdown", e)
	}
	if released.Load() != 1 {
		t.Fatal("native host was not released exactly once")
	}
	before := protected.Load()
	if e = platform.AutoDetectInterfaceControl(1); e == nil {
		t.Fatal("protection callback invoked after release")
	}
	if protected.Load() != before {
		t.Fatal("released native host was called")
	}
}

func TestFailedStartReleasesCaptureAndHost(t *testing.T) {
	pair, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(pair[1])
	var released atomic.Int32
	platform, e := New(pair[0], Hooks{Protect: func(int) error { return nil }, Interfaces: func() ([]adapter.NetworkInterface, error) { return nil, nil }, Release: func() { released.Add(1) }})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Start(context.Background(), platform, []byte(`{"unexpected":true}`)); e == nil {
		t.Fatal("accepted invalid session")
	}
	if _, e = unix.FcntlInt(uintptr(pair[0]), unix.F_GETFD, 0); e != unix.EBADF {
		t.Fatal("failed start leaked FD")
	}
	if released.Load() != 1 {
		t.Fatal("failed start leaked host")
	}
}

func dnsPacket(t *testing.T) []byte {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("packet.test.", dns.TypeA)
	payload, e := query.Pack()
	if e != nil {
		t.Fatal(e)
	}
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], net.ParseIP("172.19.0.10").To4())
	copy(packet[16:20], net.ParseIP("172.19.0.2").To4())
	binary.BigEndian.PutUint16(packet[20:22], 53000)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	return packet
}

func TestPublicPacketFlowManagedDNSAndCleanup(t *testing.T) {
	replies := make(chan []byte, 4)
	var writes, released atomic.Int32
	flow, err := NewPacketFlow(1280, func(packet []byte) error {
		writes.Add(1)
		replies <- append([]byte(nil), packet...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	platform, err := New(-1, Hooks{
		Protect:          func(int) error { return nil },
		Interfaces:       func() ([]adapter.NetworkInterface, error) { return nil, nil },
		Open:             func(*tun.Options) (tun.Tun, error) { return flow, nil },
		Release:          func() { released.Add(1) },
		NetworkExtension: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := Start(context.Background(), platform, sampleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err = flow.Feed(dnsPacket(t)); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-replies:
		if len(packet) < 28 {
			t.Fatal("short packet")
		}
		var answer dns.Msg
		if err = answer.Unpack(packet[28:]); err != nil {
			t.Fatal(err)
		}
		if len(answer.Answer) != 1 {
			t.Fatal("missing FakeIP answer")
		}
		addr, ok := answer.Answer[0].(*dns.A)
		if !ok || !netip.MustParsePrefix("198.18.0.0/15").Contains(netip.MustParseAddr(addr.A.String())) {
			t.Fatal("public packet flow bypassed managed DNS")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no DNS reply via public packet flow")
	}
	session.Close()
	before := writes.Load()
	if err = flow.Feed(dnsPacket(t)); err == nil {
		t.Fatal("accepted packet after stop")
	}
	if _, err = flow.Write([]byte{0x45}); err == nil {
		t.Fatal("native write after stop")
	}
	if writes.Load() != before || released.Load() != 1 {
		t.Fatal("host lifetime violation")
	}
}
