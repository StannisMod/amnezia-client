//go:build linux && !android

package engine

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stabilityMTUPeer(t *testing.T, config awg.Config) (netip.AddrPort, net.Listener) {
	t.Helper()
	if mode := os.Getenv("AMNEZIA_STABILITY_LAB"); mode != "isolated-container" && mode != "isolated-namespace" {
		t.Fatal("kernel peer requires the isolated lab wrapper")
	}
	command := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v %s", args, e, b)
		}
	}
	command("netns", "add", "stability-peer")
	t.Cleanup(func() { exec.Command("ip", "netns", "del", "stability-peer").Run() })
	command("link", "add", "stb-underlay", "type", "veth", "peer", "name", "eth0", "netns", "stability-peer")
	// Deleting the named namespace alone is insufficient while kernel socket
	// references are still draining. Remove only this fixture's owned pair.
	t.Cleanup(func() { exec.Command("ip", "link", "del", "stb-underlay").Run() })
	command("addr", "add", "203.0.113.1/24", "dev", "stb-underlay")
	command("link", "set", "stb-underlay", "up")
	command("-n", "stability-peer", "link", "set", "lo", "up")
	command("-n", "stability-peer", "addr", "add", "203.0.113.2/24", "dev", "eth0")
	command("-n", "stability-peer", "link", "set", "eth0", "up")
	command("route", "add", "default", "via", "203.0.113.2", "dev", "stb-underlay")
	command("netns", "add", "mtu-origin")
	t.Cleanup(func() { exec.Command("ip", "netns", "del", "mtu-origin").Run() })
	command("-n", "stability-peer", "link", "add", "originlink", "type", "veth", "peer", "name", "wan", "netns", "mtu-origin")
	command("-n", "stability-peer", "addr", "add", "192.0.2.1/30", "dev", "originlink")
	command("-n", "stability-peer", "link", "set", "originlink", "up")
	command("netns", "exec", "stability-peer", "sysctl", "-qw", "net.ipv4.ip_forward=1")
	command("-n", "mtu-origin", "link", "set", "lo", "up")
	command("-n", "mtu-origin", "link", "set", "wan", "up")
	command("-n", "mtu-origin", "addr", "add", "192.0.2.2/30", "dev", "wan")
	command("-n", "mtu-origin", "addr", "add", config.Address[0].String()+"/32", "dev", "lo")
	command("-n", "mtu-origin", "route", "add", "default", "via", "192.0.2.1")
	var listener net.Listener
	var endpoint netip.AddrPort
	withStabilityNS(t, "/run/netns/stability-peer", func() error {
		mtu := 1280
		if value := os.Getenv("MTU_LAB_SERVER_MTU"); value != "" {
			if _, err := fmt.Sscan(value, &mtu); err != nil || mtu < 1280 || mtu > 1500 {
				return fmt.Errorf("invalid MTU lab value")
			}
		}
		packet, e := tun.CreateTUN("stb-peer", mtu)
		if e != nil {
			return e
		}
		key := func(v string) string { b, _ := base64.StdEncoding.DecodeString(v); return hex.EncodeToString(b) }
		ipc := fmt.Sprintf("private_key=%s\nlisten_port=0\n", key(config.PrivateKey))
		for k, v := range config.Parameters {
			ipc += k + "=" + v + "\n"
		}
		ipc += fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s\n", key(config.PublicKey), config.AllowedIPs[0])
		device, e := awg.NewConfiguredDevice(packet, conn.NewStdNetBind(), ipc)
		if e != nil {
			return e
		}
		t.Cleanup(device.Close)
		state, e := device.IpcGet()
		if e != nil {
			return e
		}
		var port int
		for _, line := range strings.Split(state, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				fmt.Sscanf(line, "listen_port=%d", &port)
			}
		}
		endpoint = netip.AddrPortFrom(netip.MustParseAddr("203.0.113.2"), uint16(port))
		address := config.Address[0]
		prefix := "/32"
		if address.Is6() {
			prefix = "/128"
		}
		// These commands inherit this locked OS thread's namespace.
		command("addr", "add", "10.77.0.254"+prefix, "dev", "stb-peer")
		command("route", "add", address.String()+prefix, "via", "192.0.2.2")
		command("link", "set", "stb-peer", "up")
		if address.Is6() {
			command("-6", "route", "add", config.AllowedIPs[0].String(), "dev", "stb-peer")
		} else {
			command("route", "add", config.AllowedIPs[0].String(), "dev", "stb-peer")
		}
		secondPrivate, secondPublic := keys(t)
		if err := device.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=10.77.0.3/32\n", key(secondPublic))); err != nil {
			return err
		}
		command("route", "add", "10.77.0.3/32", "dev", "stb-peer")
		raw, _ := base64.StdEncoding.DecodeString(config.PrivateKey)
		priv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return err
		}
		sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		second, err := awg.New(context.Background(), awg.Config{PrivateKey: secondPrivate, PublicKey: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), Address: []netip.Addr{netip.MustParseAddr("10.77.0.3")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")}, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), Parameters: config.Parameters, MTU: 1280}, func(context.Context, string, string) (net.PacketConn, error) { return sock, nil })
		if err != nil {
			return err
		}
		t.Cleanup(func() { second.Close() })
		var stream net.Listener
		withStabilityNS(t, "/run/netns/mtu-origin", func() error { var err error; stream, err = net.Listen("tcp", "10.77.0.2:18444"); return err })
		t.Cleanup(func() { stream.Close() })
		go func() {
			c, e := stream.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			b := make([]byte, 4096)
			for {
				if _, e := c.Write(b); e != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		c, err := second.DialContext(ctx, "tcp", "10.77.0.2:18444")
		cancel()
		if err != nil {
			return err
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			var n int
			b := make([]byte, 4096)
			for {
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				n++
				if n%5 == 0 {
					path := filepath.Join(os.Getenv("AMNEZIA_STABILITY_TRACE"), "healthy-records")
					os.WriteFile(path+".tmp", []byte(fmt.Sprint(n)), 0644)
					os.Rename(path+".tmp", path)
				}
			}
		}()
		withStabilityNS(t, "/run/netns/mtu-origin", func() error { listener, e = net.Listen("tcp", net.JoinHostPort(address.String(), "18443")); return e })
		if e == nil && os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
			endpoint = stabilityDomainFrontdoors(t, endpoint)
		}
		return e
	})
	if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
		command("route", "add", "1.1.1.1/32", "via", "203.0.113.2", "dev", "stb-underlay")
	}
	return endpoint, listener
}
