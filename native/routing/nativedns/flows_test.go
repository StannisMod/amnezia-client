package nativedns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func flowQuery(t *testing.T, f *Flows, endpoint netip.AddrPort, network string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("native-flow.test.", qtype)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wire []byte
	if network == "tcp" {
		c, handled, err := f.Open(ctx, network, endpoint)
		if err != nil || !handled {
			t.Fatalf("TCP admission: %v/%v", handled, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		dc := &dns.Conn{Conn: c}
		if err := dc.WriteMsg(q); err != nil {
			t.Fatal(err)
		}
		a, err := dc.ReadMsg()
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	c, handled, err := f.OpenPacket(ctx, endpoint)
	if err != nil || !handled {
		t.Fatalf("UDP admission: %v/%v", handled, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	wire, err = q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo(wire, net.UDPAddrFromAddrPort(endpoint)); err != nil {
		t.Fatal(err)
	}
	wire = make([]byte, 4096)
	n, from, err := c.ReadFrom(wire)
	if err != nil || from.String() != endpoint.String() {
		t.Fatalf("UDP identity: %v/%v", from, err)
	}
	a := new(dns.Msg)
	if err := a.Unpack(wire[:n]); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNativeFlowsIPv6OnlyAndQuiesce(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		calls.Add(1)
		return nil, ErrScopeUnavailable
	}
	endpoint := netip.MustParseAddrPort("198.19.255.1:53")
	f, err := NewFlows(context.Background(), []Binding{{Endpoint: endpoint,
		Upstream: netip.MustParseAddrPort("[fd77::2]:53")}}, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, quiesced := range []bool{false, true} {
		if quiesced {
			f.Quiesce()
			f.Quiesce()
		}
		for _, transport := range []string{"udp", "tcp"} {
			a := flowQuery(t, f, endpoint, transport, dns.TypeAAAA)
			if a.Rcode != dns.RcodeSuccess || len(a.Answer) != 0 {
				t.Fatalf("not NODATA: %v", a)
			}
			a = flowQuery(t, f, endpoint, transport, dns.TypeA)
			if a.Rcode != dns.RcodeServerFailure {
				t.Fatalf("not fail-closed: %v", a)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("IPv6 upstream transport attempted")
	}
	if _, handled, err := f.Open(context.Background(), "tcp", netip.MustParseAddrPort("192.0.2.8:443")); handled || err != nil {
		t.Fatal("ordinary IPv4 flow intercepted")
	}
	if _, handled, err := f.Open(context.Background(), "tcp", netip.MustParseAddrPort("[fd77::8]:443")); !handled || err == nil {
		t.Fatal("literal IPv6 delegated to native proxy")
	}
}

func TestNativeFlowsNeverFlattenSelectedEncryptedTransport(t *testing.T) {
	endpoint := netip.MustParseAddrPort("198.19.255.1:53")
	upstream := netip.MustParseAddrPort("192.0.2.53:853")
	var calls atomic.Int32
	dial := func(_ context.Context, network string, target netip.AddrPort) (net.Conn, error) {
		if network != "tcp4" || target != upstream {
			t.Errorf("encrypted flow downgraded/substituted: %s %v", network, target)
		}
		calls.Add(1)
		return nil, ErrScopeUnavailable
	}
	f, err := NewFlows(context.Background(), []Binding{{Endpoint: endpoint, Upstream: upstream,
		Transport: "tls", ServerName: "selected.invalid"}}, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, network := range []string{"udp", "tcp"} {
		if answer := flowQuery(t, f, endpoint, network, dns.TypeAAAA); answer.Rcode != dns.RcodeSuccess {
			t.Fatal("encrypted flow disabled local NODATA")
		}
		if answer := flowQuery(t, f, endpoint, network, dns.TypeA); answer.Rcode != dns.RcodeServerFailure {
			t.Fatal("missing original encrypted scope did not fail closed")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("AAAA dialed or encrypted failure fell back")
	}
	for _, binding := range []Binding{
		{Endpoint: endpoint, Upstream: upstream, Transport: "unknown"},
		{Endpoint: endpoint, Upstream: upstream, Transport: "plain", ServerName: "selected.invalid"},
	} {
		if invalid, err := NewFlows(context.Background(), []Binding{binding}, dial); err == nil {
			invalid.Close()
			t.Fatal("native flow erased unsupported security metadata")
		}
	}
}

func TestNativeFlowsForwardingAndResolverIdentity(t *testing.T) {
	var udpCalls, tcpCalls atomic.Int32
	// A real UDP/TCP upstream, distinct from the managed DNS listeners.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		a := new(dns.Msg)
		a.SetReply(q)
		a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name,
			Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(192, 0, 2, 9)}}
		_ = w.WriteMsg(a)
	})
	ready := make(chan struct{}, 2)
	tcpServer := &dns.Server{Listener: listener, Handler: handler, NotifyStartedFunc: func() { ready <- struct{}{} }}
	udpServer := &dns.Server{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { ready <- struct{}{} }}
	go tcpServer.ActivateAndServe()
	go udpServer.ActivateAndServe()
	<-ready
	<-ready
	defer tcpServer.Shutdown()
	defer udpServer.Shutdown()
	selected := netip.MustParseAddrPort("192.0.2.53:53")
	dial := func(ctx context.Context, network string, target netip.AddrPort) (net.Conn, error) {
		if target != selected {
			t.Errorf("substituted resolver: %v", target)
			return nil, ErrScopeUnavailable
		}
		if network == "udp4" {
			udpCalls.Add(1)
		} else if network == "tcp4" {
			tcpCalls.Add(1)
		} else {
			t.Errorf("substituted transport: %v", network)
			return nil, ErrScopeUnavailable
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}
	first := netip.MustParseAddrPort("198.19.255.1:53")
	second := netip.MustParseAddrPort("198.19.255.2:53")
	f, err := NewFlows(context.Background(), []Binding{{Endpoint: first, Upstream: selected},
		{Endpoint: second, Upstream: selected}}, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, endpoint := range []netip.AddrPort{first, second} {
		for _, transport := range []string{"udp", "tcp"} {
			a := flowQuery(t, f, endpoint, transport, dns.TypeA)
			if a.Rcode != dns.RcodeSuccess || len(a.Answer) != 1 {
				t.Fatalf("A lost: %v", a)
			}
		}
	}
	if udpCalls.Load() != 2 || tcpCalls.Load() != 2 {
		t.Fatalf("transport/order occurrences: %d/%d", udpCalls.Load(), tcpCalls.Load())
	}
	c, handled, err := f.OpenPacket(context.Background(), first)
	if err != nil || !handled {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WriteTo([]byte("wrong target"), net.UDPAddrFromAddrPort(second)); err == nil {
		t.Fatal("UDP association changed resolver occurrence")
	}
	f.Quiesce()
	for _, transport := range []string{"udp", "tcp"} {
		if a := flowQuery(t, f, first, transport, dns.TypeA); a.Rcode != dns.RcodeServerFailure {
			t.Fatal(a)
		}
	}
}

func TestNativeFlowsCloseAndValidation(t *testing.T) {
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) { return nil, ErrScopeUnavailable }
	endpoint := netip.MustParseAddrPort("198.19.255.1:53")
	binding := Binding{Endpoint: endpoint, Upstream: netip.MustParseAddrPort("192.0.2.53:53")}
	for _, bindings := range [][]Binding{nil, {binding, binding},
		{{Endpoint: endpoint, Upstream: endpoint}}, {{Endpoint: endpoint, Upstream: binding.Upstream, InterfaceName: "underlay"}}} {
		if f, err := NewFlows(context.Background(), bindings, dial); err == nil {
			f.Close()
			t.Fatal("invalid native scope accepted")
		}
	}
	f, err := NewFlows(context.Background(), []Binding{binding}, dial)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := f.Open(context.Background(), "tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.Done():
	default:
		t.Fatal("close not published")
	}
	if _, handled, err := f.Open(context.Background(), "tcp", endpoint); !handled || err == nil {
		t.Fatal("closed native flow owner reopened")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("borrowed native stream remained open")
	}
}

func TestNativeFlowsRaceBorrowedClose(t *testing.T) {
	dial := func(context.Context, string, netip.AddrPort) (net.Conn, error) {
		return nil, ErrScopeUnavailable
	}
	endpoint := netip.MustParseAddrPort("198.19.255.1:53")
	for i := 0; i < 20; i++ {
		f, err := NewFlows(context.Background(), []Binding{{Endpoint: endpoint,
			Upstream: netip.MustParseAddrPort("192.0.2.53:53")}}, dial)
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := f.Open(context.Background(), "udp", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
	}
}
