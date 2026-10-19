package awg

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

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
		n, from, e := udp.ReadFrom(p)
		if e == nil {
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
