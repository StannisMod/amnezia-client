//go:build linux && with_gvisor

package mobile

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/dnspolicy"
	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/StannisMod/amnezia-client/native/routing/wireguard"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func TestNetworkDNSReloadRepreparesOriginalPolicy(t *testing.T) {
	var session engine.SessionConfig
	if err := json.Unmarshal(sampleConfig(t), &session); err != nil {
		t.Fatal(err)
	}
	session.DNS = &dnspolicy.Config{Version: 1, Default: "local", PreserveNetworkDomains: true, Policies: map[string]dnspolicy.Resolver{"local": {Source: "network", Transport: "udp", Path: rules.Direct}}}
	snapshot := func(iface, server, domain string) dnspolicy.NetworkSnapshot {
		return dnspolicy.NetworkSnapshot{RoutingDomainsAvailable: true, Links: []dnspolicy.NetworkLink{{ID: "7", Interface: iface, Default: true, Domains: []string{domain}, Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr(server)}}}}}
	}
	first := snapshot("network-a", "192.0.2.53", "old.example")
	session.NetworkDNS = &first
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	original := string(raw)
	compiled, _, err := compileSession(raw)
	if err != nil {
		t.Fatal(err)
	}
	var before map[string]any
	if err = json.Unmarshal(compiled, &before); err != nil {
		t.Fatal(err)
	}
	second := snapshot("network-b", "198.51.100.53", "new.example")
	updated, _, err := compileSessionSnapshot(raw, &second)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	if err = json.Unmarshal(updated, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before["route"], after["route"]) {
		t.Fatal("DNS reload changed application routing")
	}
	vpn := func(options map[string]any) any {
		for _, v := range options["outbounds"].([]any) {
			row := v.(map[string]any)
			if row["tag"] == "vpn" {
				return row
			}
		}
		return nil
	}
	if !reflect.DeepEqual(vpn(before), vpn(after)) {
		t.Fatal("DNS reload changed VPN identity")
	}
	encoded := string(updated)
	if strings.Contains(encoded, "old.example") || strings.Contains(encoded, "192.0.2.53") || strings.Contains(encoded, "network-a") || !strings.Contains(encoded, "new.example") || !strings.Contains(encoded, "198.51.100.53") || !strings.Contains(encoded, "network-b") {
		t.Fatal("old native DNS data survived replacement")
	}
	if string(raw) != original {
		t.Fatal("original network-source policy mutated")
	}
	if _, _, err = compileSessionSnapshot(raw, &dnspolicy.NetworkSnapshot{}); err == nil {
		t.Fatal("empty inventory fell back to previous snapshot")
	}
}

func TestMobileNetworkDNSIsPreparedBeforeCapture(t *testing.T) {
	var session engine.SessionConfig
	if err := json.Unmarshal(sampleConfig(t), &session); err != nil {
		t.Fatal(err)
	}
	session.DNS = &dnspolicy.Config{Version: 1, Default: "local", Policies: map[string]dnspolicy.Resolver{"local": {Source: "network", Transport: "udp", Path: rules.Direct}}}
	raw, _ := json.Marshal(session)
	if Validate(raw) == nil {
		t.Fatal("missing native snapshot was silently accepted")
	}
	session.NetworkDNS = &dnspolicy.NetworkSnapshot{Links: []dnspolicy.NetworkLink{{ID: "native", Interface: "network-42", Default: true, Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.168.10.53")}}}}}
	raw, _ = json.Marshal(session)
	if err := Validate(raw); err != nil {
		t.Fatal(err)
	}
}

func TestNativeOpportunisticTLSRetainedBySerializedSession(t *testing.T) {
	for _, opportunistic := range []bool{false, true} {
		var session engine.SessionConfig
		if err := json.Unmarshal(sampleConfig(t), &session); err != nil {
			t.Fatal(err)
		}
		session.DNS = &dnspolicy.Config{Version: 1, Default: "local", PreserveNetworkDomains: true,
			Policies: map[string]dnspolicy.Resolver{"local": {Source: "network", Transport: "udp", Path: rules.Direct}}}
		session.NetworkDNS = &dnspolicy.NetworkSnapshot{RoutingDomainsAvailable: true, Links: []dnspolicy.NetworkLink{{
			ID: "7", Interface: "corp0", Default: true, Domains: []string{"corp.example"},
			Servers: []dnspolicy.NetworkServer{{Address: netip.MustParseAddr("192.0.2.53"), Port: 8853,
				Transport: "tls", ServerName: "dns.corp.example", OpportunisticTLS: opportunistic}},
		}}}
		raw, err := json.Marshal(session)
		if err != nil {
			t.Fatal(err)
		}
		compiled, _, err := compileSession(raw)
		if err != nil {
			t.Fatal(err)
		}
		var output struct {
			DNS struct {
				Servers []struct {
					Tag  string `json:"tag"`
					Type string `json:"type"`
					Port int    `json:"server_port"`
					TLS  struct {
						Insecure   bool   `json:"insecure"`
						ServerName string `json:"server_name"`
					} `json:"tls"`
				} `json:"servers"`
			} `json:"dns"`
		}
		if err := json.Unmarshal(compiled, &output); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, server := range output.DNS.Servers {
			if server.Tag != dnspolicy.Tag("local") && server.Tag != dnspolicy.Tag("network-7") {
				continue
			}
			found++
			if server.Type != "tls" || server.Port != 8853 || server.TLS.ServerName != "dns.corp.example" || server.TLS.Insecure != opportunistic {
				t.Fatalf("native TLS mode lost after JSON and compileSession: %+v", server)
			}
		}
		if found != 2 {
			t.Fatal("missing network policies", found)
		}
	}
}

func sampleConfig(t *testing.T, transport ...string) []byte {
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
	if len(transport) > 0 && transport[0] == "wireguard" {
		var session engine.SessionConfig
		if err := json.Unmarshal(raw, &session); err != nil {
			t.Fatal(err)
		}
		c := session.AWG
		session.VPN = &engine.TransportConfig{Type: "wireguard", WireGuard: &wireguard.Config{Address: c.Address, PrivateKey: c.PrivateKey, PublicKey: c.PublicKey, Endpoint: c.Endpoint, AllowedIPs: c.AllowedIPs}}
		session.AWG = awg.Config{}
		raw, e = json.Marshal(session)
		if e != nil {
			t.Fatal(e)
		}
	}
	return raw
}

// Use a datagram FD as a packet source, exercising NativeTun and its real
// gVisor FD endpoint without claiming an Android VpnService/device test.
func TestOwnedPacketFDManagedDNSAndCleanup(t *testing.T) {
	for _, transport := range []string{"awg", "wireguard"} {
		t.Run(transport, func(t *testing.T) { testOwnedPacketFDManagedDNSAndCleanup(t, transport, false) })
	}
}
func TestNetworkDNSReloadKeepsNativePacketOwner(t *testing.T) {
	for _, transport := range []string{"awg", "wireguard"} {
		t.Run(transport, func(t *testing.T) { testOwnedPacketFDManagedDNSAndCleanup(t, transport, true) })
	}
}
func TestLiveAndroidPolicyKeepsNativePacketOwner(t *testing.T) {
	for _, transport := range []string{"awg", "wireguard"} {
		t.Run(transport, func(t *testing.T) { testOwnedPacketFDManagedDNSAndCleanup(t, transport, true, true) })
	}
}

func testOwnedPacketFDManagedDNSAndCleanup(t *testing.T, transport string, networkDNS bool, liveMode ...bool) {
	live := len(liveMode) != 0 && liveMode[0]
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
	start := Start
	if networkDNS {
		start = StartWithNetworkDNS
	}
	raw := sampleConfig(t, transport)
	if live {
		var config map[string]any
		json.Unmarshal(raw, &config)
		config["android_applications"] = map[string]any{"live": true, "site_rules_uids": []uint32{10282}}
		raw, _ = json.Marshal(config)
	}
	session, e := start(ctx, platform, raw)
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
	if live {
		beforeCore, beforeCapture := session.core, platform.capture
		if e = session.UpdateAndroidApplications([]byte(`{"live":true,"site_rules_uids":[10281]}`)); e != nil {
			t.Fatal(e)
		}
		if session.core != beforeCore || platform.capture != beforeCapture || released.Load() != 0 {
			t.Fatal("policy update replaced packet owner")
		}
		var saved struct {
			Applications struct {
				UIDs []uint32 `json:"site_rules_uids"`
			} `json:"android_applications"`
		}
		json.Unmarshal(session.networkDNSConfig, &saved)
		if len(saved.Applications.UIDs) != 1 || saved.Applications.UIDs[0] != 10281 {
			t.Fatal("policy not retained for future network DNS reload")
		}
		session.SuspendNetworkDNS()
		if e = session.UpdateAndroidApplications([]byte(`{"live":true,"site_rules_uids":[10282]}`)); e == nil {
			t.Fatal("application update revived unavailable network DNS")
		}
		if e = session.ReloadNetworkDNS(dnspolicy.NetworkSnapshot{}); e != nil {
			t.Fatal(e)
		}
		if e = session.UpdateAndroidApplications([]byte(`{"live":true,"site_rules_uids":[10282]}`)); e != nil {
			t.Fatal(e)
		}
	}
	if networkDNS {
		for range 3 {
			session.SuspendNetworkDNS()
			if e = session.ReloadNetworkDNS(dnspolicy.NetworkSnapshot{}); e != nil {
				t.Fatal(e)
			}
			if released.Load() != 0 {
				t.Fatal("DNS generation released native platform")
			}
			if e = platform.AutoDetectInterfaceControl(pair[0]); e != nil {
				t.Fatal("DNS generation invalidated native protection", e)
			}
			if _, e = app.Write(packet); e != nil {
				t.Fatal(e)
			}
			n, e = app.Read(reply)
			if e != nil {
				t.Fatal("DNS reload lost capture reader", e)
			}
			if n < 28 {
				t.Fatal("truncated response after DNS reload")
			}
			if e = answer.Unpack(reply[28:n]); e != nil {
				t.Fatal(e)
			}
			if len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).A.String() != fake {
				t.Fatal("DNS reload replaced FakeIP identity")
			}
		}
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
	// Match the source address actually assigned by Android's VpnService.
	copy(packet[12:16], net.ParseIP("172.19.0.1").To4())
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
	for _, transport := range []string{"awg", "wireguard"} {
		t.Run(transport, func(t *testing.T) { testPublicPacketFlowManagedDNSAndCleanup(t, transport) })
	}
}
func testPublicPacketFlowManagedDNSAndCleanup(t *testing.T, transport string) {
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
	session, err := Start(context.Background(), platform, sampleConfig(t, transport))
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

// FD ownership alone misses auxiliary descriptors allocated by the capture
// endpoint. Reconnect in one process, as Android does, and count eventfds too.
func TestCaptureReconnectDoesNotLeakEventFD(t *testing.T) {
	for _, transport := range []string{"awg", "wireguard"} {
		t.Run(transport, func(t *testing.T) { testCaptureReconnectDoesNotLeakEventFD(t, transport) })
	}
}
func testCaptureReconnectDoesNotLeakEventFD(t *testing.T, transport string) {
	eventfds := func() int {
		rows, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rows {
			target, _ := os.Readlink("/proc/self/fd/" + r.Name())
			if target == "anon_inode:[eventfd]" {
				n++
			}
		}
		return n
	}
	cycle := func() {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[1])
		p, err := New(pair[0], Hooks{Protect: func(int) error { return nil }, Interfaces: func() ([]adapter.NetworkInterface, error) {
			return []adapter.NetworkInterface{{Interface: control.Interface{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}}}, nil
		}})
		if err != nil {
			unix.Close(pair[0])
			t.Fatal(err)
		}
		s, err := Start(context.Background(), p, sampleConfig(t, transport))
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	cycle() // initialize the process-wide Go poller before taking the baseline
	before := eventfds()
	for i := 0; i < 10; i++ {
		cycle()
	}
	after := eventfds()
	if after > before {
		t.Fatalf("capture eventfds grew across 10 reconnects: %d -> %d", before, after)
	}
}

func TestValidationDoesNotCreateCaptureOrCache(t *testing.T) {
	var config map[string]any
	if err := json.Unmarshal(sampleConfig(t), &config); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/not-created/fakeip.db"
	config["cache_path"] = path
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate(raw); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("preflight touched the cache", err)
	}
	config["rules"].(map[string]any)["version"] = 99
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate(raw); err == nil {
		t.Fatal("preflight accepted unsupported rule schema")
	}
}

func TestMobileKeepaliveValidation(t *testing.T) {
	for _, value := range []any{"25-35", "25", "0", 25, "35-25", "25\nlisten_port=1", "4294967296"} {
		var config map[string]any
		if err := json.Unmarshal(sampleConfig(t), &config); err != nil {
			t.Fatal(err)
		}
		config["awg"].(map[string]any)["keepalive"] = value
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		err = Validate(raw)
		valid := value == "25-35" || value == "25" || value == "0" || value == 25
		if (err == nil) != valid {
			t.Fatalf("keepalive %v: %v", value, err)
		}
	}
}

func TestTransportFailureReleasesCapture(t *testing.T) {
	for _, transport := range []string{"awg", "wireguard"} {
		for _, stage := range []string{"socket", "capture"} {
			t.Run(transport+"/"+stage, func(t *testing.T) {
				pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(pair[1])
				var released atomic.Int32
				hooks := Hooks{Interfaces: func() ([]adapter.NetworkInterface, error) { return nil, nil }, Release: func() { released.Add(1) }, Protect: func(int) error {
					if stage == "socket" {
						return errors.New("controlled protection failure")
					}
					return nil
				}}
				if stage == "capture" {
					hooks.Open = func(*tun.Options) (tun.Tun, error) { return nil, errors.New("controlled capture failure") }
				}
				platform, err := New(pair[0], hooks)
				if err != nil {
					t.Fatal(err)
				}
				if session, err := Start(context.Background(), platform, sampleConfig(t, transport)); err == nil {
					session.Close()
					t.Fatal("controlled startup failure was ignored")
				}
				if _, err := unix.FcntlInt(uintptr(pair[0]), unix.F_GETFD, 0); err != unix.EBADF {
					t.Fatal("failed startup leaked capture", err)
				}
				if released.Load() != 1 {
					t.Fatal("host must be released exactly once", released.Load())
				}
			})
		}
	}
}

func TestTypedWireGuardSessionSchema(t *testing.T) {
	raw := sampleConfig(t, "wireguard")
	if err := Validate(raw); err != nil {
		t.Fatal("valid WG envelope", err)
	}
	for _, mutate := range []func(map[string]any){
		func(c map[string]any) { c["vpn"].(map[string]any)["type"] = "openvpn" },
		func(c map[string]any) {
			c["vpn"].(map[string]any)["wireguard"].(map[string]any)["parameters"] = map[string]any{"jc": "3"}
		},
		func(c map[string]any) { c["vpn"].(map[string]any)["wireguard"].(map[string]any)["keepalive"] = "25-35" },
		func(c map[string]any) { c["vpn"].(map[string]any)["wireguard"].(map[string]any)["keepalive"] = 65536 },
		func(c map[string]any) { c["vpn"].(map[string]any)["awg"] = map[string]any{} },
	} {
		var config map[string]any
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		mutate(config)
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if Validate(encoded) == nil {
			t.Fatal("accepted an unsupported WG transport setting")
		}
	}
}
