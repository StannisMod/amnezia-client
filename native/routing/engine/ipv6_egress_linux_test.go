//go:build linux && !android

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/rules"
	"github.com/StannisMod/amnezia-client/native/routing/wireguard"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestEncryptedIPv6KernelEgress(t *testing.T) {
	if os.Getenv("AMNEZIA_IPV6_LAB") != "isolated-namespace" {
		t.Skip("requires isolated IPv6 Docker wrapper")
	}
	links, err := exec.Command("ip", "-j", "link").Output()
	if err != nil {
		t.Fatal(err)
	}
	var inventory []struct {
		Name string `json:"ifname"`
	}
	if json.Unmarshal(links, &inventory) != nil || len(inventory) != 1 || inventory[0].Name != "lo" {
		t.Fatal("IPv6 lab requires a fresh loopback-only namespace")
	}
	for _, protocol := range []string{"awg", "wireguard"} {
		t.Run(protocol, testEncryptedIPv6KernelEgress)
	}
}

func testEncryptedIPv6KernelEgress(t *testing.T) {
	protocol := t.Name()[strings.LastIndex(t.Name(), "/")+1:]
	command := func(args ...string) {
		t.Helper()
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, output)
		}
	}
	command("netns", "add", "v6-peer")
	t.Cleanup(func() { exec.Command("ip", "netns", "del", "v6-peer").Run() })
	command("netns", "add", "v6-origin")
	t.Cleanup(func() { exec.Command("ip", "netns", "del", "v6-origin").Run() })
	command("link", "add", "v6-outer", "type", "veth", "peer", "name", "outer0", "netns", "v6-peer")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "v6-outer").Run() })
	command("addr", "add", "203.0.113.1/24", "dev", "v6-outer")
	command("link", "set", "v6-outer", "up")
	command("-n", "v6-peer", "link", "set", "lo", "up")
	command("-n", "v6-peer", "addr", "add", "203.0.113.2/24", "dev", "outer0")
	command("-n", "v6-peer", "link", "set", "outer0", "up")
	command("-n", "v6-peer", "link", "add", "eth0", "type", "veth", "peer", "name", "origin0", "netns", "v6-origin")
	command("-n", "v6-peer", "link", "set", "eth0", "up")
	command("-n", "v6-peer", "-6", "addr", "add", "fd88::2/64", "dev", "eth0", "nodad")
	command("-n", "v6-peer", "-6", "route", "add", "default", "via", "fd88::1", "dev", "eth0")
	command("-n", "v6-origin", "link", "set", "lo", "up")
	command("-n", "v6-origin", "link", "set", "origin0", "up")
	command("-n", "v6-origin", "-6", "addr", "add", "fd88::1/64", "dev", "origin0", "nodad")
	clientPrivate, clientPublic := keys(t)
	serverPrivate, serverPublic := keys(t)
	key := func(value string) string {
		b, _ := base64.StdEncoding.DecodeString(value)
		return hex.EncodeToString(b)
	}
	parameters := map[string]string(nil)
	if protocol == "awg" {
		parameters = map[string]string{"s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
	}
	var serverPort uint16
	withStabilityNS(t, "/run/netns/v6-peer", func() error {
		packet, err := tun.CreateTUN("wg0", 1280)
		if err != nil {
			return err
		}
		ipc := fmt.Sprintf("private_key=%s\nlisten_port=0\n", key(serverPrivate))
		for k, v := range parameters {
			ipc += k + "=" + v + "\n"
		}
		ipc += fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=fd77::2/128\n", key(clientPublic))
		device, err := awg.NewConfiguredDevice(packet, conn.NewStdNetBind(), ipc)
		if err != nil {
			return err
		}
		t.Cleanup(device.Close)
		state, err := device.IpcGet()
		if err != nil {
			return err
		}
		for _, line := range strings.Split(state, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				fmt.Sscanf(line, "listen_port=%d", &serverPort)
			}
		}
		command("-6", "addr", "add", "fd77::1/64", "dev", "wg0", "nodad")
		command("link", "set", "wg0", "up")
		output, err := exec.Command("sh", "-ec", ". /app/enable_ipv6_forwarding.sh; amnezia_enable_ipv6 wg0").CombinedOutput()
		if err != nil {
			return fmt.Errorf("IPv6 forwarding: %v %s", err, output)
		}
		return nil
	})
	var origin net.Listener
	var udpOrigin net.PacketConn
	withStabilityNS(t, "/run/netns/v6-origin", func() error {
		var err error
		origin, err = net.Listen("tcp6", "[fd88::1]:0")
		if err != nil {
			return err
		}
		udpOrigin, err = net.ListenPacket("udp6", "[fd88::1]:0")
		return err
	})
	defer origin.Close()
	defer udpOrigin.Close()
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	digest := sha256.Sum256(payload)
	observed := make(chan string, 1)
	go func() {
		connection, err := origin.Accept()
		if err != nil {
			observed <- err.Error()
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(20 * time.Second))
		data := make([]byte, len(payload))
		if _, err = io.ReadFull(connection, data); err != nil {
			observed <- err.Error()
			return
		}
		sum := sha256.Sum256(data)
		if _, err = connection.Write(sum[:]); err != nil {
			observed <- err.Error()
			return
		}
		observed <- connection.RemoteAddr().(*net.TCPAddr).IP.String()
	}()
	endpoint := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.2"), serverPort)
	transport := awg.Config{Address: []netip.Addr{netip.MustParseAddr("fd77::2")}, PrivateKey: clientPrivate, PublicKey: serverPublic, Endpoint: endpoint, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("::/0")}, MTU: 1280, Parameters: parameters}
	session := SessionConfig{Rules: rules.Config{Version: 1, Default: rules.VPN}, AWG: transport, Resolver: netip.MustParseAddrPort("10.77.0.1:53"), ResolverAction: rules.VPN}
	if protocol == "wireguard" {
		session.AWG = awg.Config{}
		session.VPN = &TransportConfig{Type: "wireguard", WireGuard: &wireguard.Config{Address: transport.Address, PrivateKey: clientPrivate, PublicKey: serverPublic, Endpoint: endpoint, AllowedIPs: transport.AllowedIPs, MTU: 1280}}
	}
	raw, err := session.Compile()
	if err != nil {
		t.Fatal(err)
	}
	var options map[string]any
	json.Unmarshal(raw, &options)
	delete(options, "inbounds")
	raw, _ = json.Marshal(options)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var dial net.Dialer
	var listen net.ListenConfig
	ctx = Context(ctx, Underlay{DialContext: dial.DialContext, ListenPacket: listen.ListenPacket})
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, loopbackTestPlatform{})
	instance, err := New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	vpn, ok := instance.Outbound().Outbound("vpn")
	if !ok {
		t.Fatal("VPN outbound missing")
	}
	port := origin.Addr().(*net.TCPAddr).Port
	connection, err := vpn.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("fd88::1", uint16(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(digest))
	if _, err = io.ReadFull(connection, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(digest[:]) {
		t.Fatal("encrypted IPv6 payload corrupted")
	}
	select {
	case remote := <-observed:
		if remote != "fd88::2" {
			t.Fatal("origin did not observe server IPv6 egress", remote)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	udpObserved := make(chan string, 1)
	go func() {
		data := make([]byte, 4096)
		n, peer, err := udpOrigin.ReadFrom(data)
		if err != nil {
			udpObserved <- err.Error()
			return
		}
		sum := sha256.Sum256(data[:n])
		_, err = udpOrigin.WriteTo(sum[:], peer)
		if err != nil {
			udpObserved <- err.Error()
			return
		}
		udpObserved <- peer.(*net.UDPAddr).IP.String()
	}()
	udpTarget := netip.MustParseAddrPort(udpOrigin.LocalAddr().String())
	packet, err := vpn.ListenPacket(ctx, M.SocksaddrFrom(udpTarget.Addr(), udpTarget.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	packet.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = packet.WriteTo(payload[:1200], net.UDPAddrFromAddrPort(udpTarget)); err != nil {
		t.Fatal(err)
	}
	udpDigest := sha256.Sum256(payload[:1200])
	response := make([]byte, 128)
	n, _, err := packet.ReadFrom(response)
	if err != nil || string(response[:n]) != string(udpDigest[:]) {
		t.Fatal("encrypted IPv6 UDP response failed", err)
	}
	select {
	case remote := <-udpObserved:
		if remote != "fd88::2" {
			t.Fatal("UDP did not use server IPv6 egress", remote)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Log("PASS: encrypted peer -> Linux TUN -> production NAT66 -> independent kernel origin, verified TCP 64 KiB and UDP 1200 bytes")
}
