package awg

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestKeepaliveJSONToUAPI(t *testing.T) {
	private, _ := keypair(t)
	_, public := keypair(t)
	for _, input := range []string{`{}`, `{"keepalive":0}`, `{"keepalive":25}`, `{"keepalive":"0"}`, `{"keepalive":"25"}`, `{"keepalive":"25-35"}`, `{"keepalive":"25-25"}`, `{"keepalive":"65536"}`} {
		t.Run(input, func(t *testing.T) {
			c := Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: private, PublicKey: public,
				Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
			if err := json.Unmarshal([]byte(input), &c); err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			json.Unmarshal([]byte(input), &fields)
			want := "0"
			if v, ok := fields["keepalive"]; ok {
				want = fmt.Sprint(v)
			}
			ipc, err := c.uapi()
			if err != nil || !strings.Contains(ipc, "persistent_keepalive_interval="+want+"\n") {
				t.Fatalf("keepalive lost: %q, %v", ipc, err)
			}
			// The engine serializes AWG into sing-box's outbound JSON and decodes it again.
			encoded, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Config
			if err = json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			got, err := decoded.uapi()
			if err != nil || got != ipc {
				t.Fatal("keepalive changed across engine JSON", err)
			}
		})
	}
	for _, input := range []string{`"35-25"`, `"25-"`, `"-25"`, `"1-2-3"`, `"4294967296"`, `"1-4294967296"`, `"25\npreshared_key=evil"`, `-1`, `25.5`, `true`, `null`, `[]`, `{}`} {
		t.Run("reject_"+input, func(t *testing.T) {
			var c Config
			if err := json.Unmarshal([]byte(`{"keepalive":`+input+`}`), &c); err == nil {
				t.Fatal("accepted invalid keepalive")
			}
		})
	}
}

func TestAWGDevicePreservesKeepaliveRange(t *testing.T) {
	private, _ := keypair(t)
	_, public := keypair(t)
	c := Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: private, PublicKey: public,
		Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Keepalive: "25-35"}
	var lc net.ListenConfig
	transport, err := New(context.Background(), c, lc.ListenPacket)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	state, err := transport.device.IpcGet()
	if err != nil || !strings.Contains(state, "persistent_keepalive_interval=25-35\n") {
		t.Fatal("AWG device did not retain keepalive range", err)
	}
	// In-process callers bypass JSON validation, so UAPI generation must check too.
	c.Keepalive = "25\nlisten_port=1"
	if _, err = c.uapi(); err == nil {
		t.Fatal("accepted keepalive UAPI injection")
	}
}

func keypair(t *testing.T) (string, string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func TestAWG31TCPUDP(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { testAWG31TCPUDP(t, "10.77.0.1", "10.77.0.2", "/32") })
	t.Run("IPv6", func(t *testing.T) { testAWG31TCPUDP(t, "fd77::1", "fd77::2", "/128") })
}

func testAWG31TCPUDP(t *testing.T, clientIP, serverIP, mask string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	aPriv, aPub := keypair(t)
	bPriv, bPub := keypair(t)
	// These are local, real UDP sockets. Platform protection is intentionally
	// not claimed by this host transport test.
	listen := func(c context.Context, n, a string) (net.PacketConn, error) {
		var lc net.ListenConfig
		return lc.ListenPacket(c, n, a)
	}
	params := map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
	b, e := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(serverIP)}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + mask)}, Parameters: params}, listen)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	port, e := b.LocalPort()
	if e != nil {
		t.Fatal(e)
	}
	a, e := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(clientIP)}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(serverIP + mask)}, Parameters: params}, listen)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	// The server learns the client's authenticated endpoint, just like AWG.
	// Its bind must accept this known local peer after the client port exists.
	aPort, e := a.LocalPort()
	if e != nil {
		t.Fatal(e)
	}
	// Rebuild server with its original port and the now-known peer port.
	b.Close()
	b, e = New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(serverIP)}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), aPort), ListenPort: port, AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + mask)}, Parameters: params}, listen)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	tcp, e := b.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 8080))
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	go func() {
		c, e := tcp.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	c, e := a.DialContext(ctx, "tcp", net.JoinHostPort(serverIP, "8080"))
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = c.Write([]byte("TCP-AWG31")); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 9)
	if _, e = io.ReadFull(c, buf); e != nil {
		t.Fatal(e)
	}
	if string(buf) != "TCP-AWG31" {
		t.Fatal(string(buf))
	}
	c.Close()
	udp, e := b.Net.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 8081))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		p := make([]byte, 2048)
		for i := 0; i < 2; i++ {
			n, from, e := udp.ReadFrom(p)
			if e != nil {
				return
			}
			udp.WriteTo(p[:n], from)
		}
	}()
	u, e := a.DialContext(ctx, "udp", net.JoinHostPort(serverIP, "8081"))
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	u.Write([]byte("UDP-AWG31"))
	n, e := u.Read(buf)
	if e != nil {
		t.Fatal(e)
	}
	if string(buf[:n]) != "UDP-AWG31" {
		t.Fatal(string(buf[:n]))
	}
	// Flow routing uses an unconnected PacketConn, unlike UDP DialContext.
	// Binding a wildcard address in the pinned AWG netstack accepted startup
	// but later failed WriteTo with "no route to host" on actual APK traffic.
	pc, e := a.ListenPacket(ctx, netip.MustParseAddr(serverIP))
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = pc.WriteTo([]byte("UDP-AWG31"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 8081))); e != nil {
		t.Fatal(e)
	}
	n, _, e = pc.ReadFrom(buf)
	if e != nil || string(buf[:n]) != "UDP-AWG31" {
		t.Fatal("unconnected UDP did not round trip", e)
	}
	a.Close()
	if _, e = a.DialContext(ctx, "tcp", net.JoinHostPort(serverIP, "8080")); e == nil {
		t.Fatal("closed transport allowed a flow")
	}
}

func TestRejectUnsafeConfig(t *testing.T) {
	priv, pub := keypair(t)
	c := Config{Address: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, PrivateKey: priv, PublicKey: pub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Parameters: map[string]string{"i1": "x\npublic_key=evil"}}
	if _, e := c.uapi(); e == nil {
		t.Fatal("accepted UAPI injection")
	}
	if _, e := New(context.Background(), c, nil); e == nil {
		t.Fatal("accepted absent socket protection")
	}
}
