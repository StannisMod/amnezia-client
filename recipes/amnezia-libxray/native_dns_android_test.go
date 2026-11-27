package libXray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/amnezia-vpn/amnezia-tun2socks/v2/metadata"
	"github.com/amnezia-vpn/amnezia-tun2socks/v2/proxy"
	"github.com/miekg/dns"
)

type nativeDNSProbeProxy struct{ calls atomic.Int32 }

var nativeDNSDelegate = errors.New("original native IPv4 backend")

type nativeDNSRejectNetwork struct {
	calls   atomic.Int32
	invalid atomic.Bool
}

func (c *nativeDNSRejectNetwork) BindDNS(fd int, token string) bool {
	c.calls.Add(1)
	if fd < 0 || token != "original-network-generation" {
		c.invalid.Store(true)
	}
	return false
}
func (c *nativeDNSRejectNetwork) DNSFailed() {}

type nativeDNSFailureObserver struct {
	entered chan struct{}
	release <-chan struct{}
	calls   atomic.Int32
}

func (c *nativeDNSFailureObserver) BindDNS(int, string) bool { return false }
func (c *nativeDNSFailureObserver) DNSFailed() {
	c.calls.Add(1)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	if c.release != nil {
		<-c.release
	}
}

func TestAndroidNativeDNSFailureJoinsObserverBeforeRetirement(t *testing.T) {
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		closeNativeDNS()
		_ = PrepareNativeDNS("")
	}()
	observer := &nativeDNSFailureObserver{entered: make(chan struct{}, 1), release: release}
	if err := RegisterNativeDNSController(observer); err != "" {
		t.Fatal(err)
	}
	if err := PrepareNativeDNS(`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"[fd77::2]:53"}]}`); err != "" {
		t.Fatal(err)
	}
	base := new(nativeDNSProbeProxy)
	p, err := nativeDNSProxy(base)
	if err != nil {
		t.Fatal(err)
	}
	androidDNS.Lock()
	s := androidDNS.session
	androidDNS.Unlock()
	// This is the actual prepared UDP/TCP frontend owner, not a fake callback.
	_ = s.flows.Close()
	select {
	case <-observer.entered:
	case <-time.After(time.Second):
		t.Fatal("missing frontend failure notification")
	}
	if err := PrepareNativeDNS(""); err == "" {
		t.Fatal("replaced failed but unjoined owner")
	}
	if err := CancelNativeDNS(); err == "" {
		t.Fatal("cancelled admitted owner without native join")
	}
	if _, err := p.DialContext(context.Background(), &M.Metadata{DstIP: netip.MustParseAddr("192.0.2.8"), DstPort: 443}); err == nil {
		t.Fatal("failed frontend admitted a new native flow")
	}
	done := make(chan struct{})
	go func() { closeNativeDNS(); close(done) }()
	select {
	case <-done:
		t.Fatal("cleanup returned before failure callback joined")
	case <-time.After(50 * time.Millisecond):
	}
	androidDNS.Lock()
	retained := androidDNS.session == s && androidDNS.running
	androidDNS.Unlock()
	if !retained {
		t.Fatal("ownership dropped behind pending callback")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback cleanup did not join")
	}
	if observer.calls.Load() != 1 || base.calls.Load() != 0 {
		t.Fatal("duplicate callback or native fallback")
	}
	if nativeDNSControl("tcp", "[fd77::2]:53") == nil {
		t.Fatal("IPv6 fence released before next connection")
	}
	if err := PrepareNativeDNS(""); err != "" {
		t.Fatal(err)
	}
}

func TestAndroidNativeDNSIntentionalCloseIsNotFrontendFailure(t *testing.T) {
	defer func() { closeNativeDNS(); _ = PrepareNativeDNS("") }()
	observer := &nativeDNSFailureObserver{entered: make(chan struct{}, 1)}
	if err := RegisterNativeDNSController(observer); err != "" {
		t.Fatal(err)
	}
	if err := PrepareNativeDNS(`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"[fd77::2]:53"}]}`); err != "" {
		t.Fatal(err)
	}
	if err := CancelNativeDNS(); err != "" {
		t.Fatal(err)
	}
	if observer.calls.Load() != 0 {
		t.Fatal("intentional close falsely notified failure")
	}
	_ = PrepareNativeDNS("")
}

func TestAndroidNativeDNSFailedPreparationCannotAdmitEngine(t *testing.T) {
	defer func() { closeNativeDNS(); _ = PrepareNativeDNS("") }()
	observer := &nativeDNSFailureObserver{entered: make(chan struct{}, 1)}
	_ = RegisterNativeDNSController(observer)
	if err := PrepareNativeDNS(`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"[fd77::2]:53"}]}`); err != "" {
		t.Fatal(err)
	}
	androidDNS.Lock()
	s := androidDNS.session
	androidDNS.Unlock()
	_ = s.flows.Close()
	select {
	case <-observer.entered:
	case <-time.After(time.Second):
		t.Fatal("missing failure")
	}
	if _, err := nativeDNSProxy(new(nativeDNSProbeProxy)); err == nil {
		t.Fatal("admitted a dead DNS generation")
	}
	if err := CancelNativeDNS(); err != "" {
		t.Fatal(err)
	}
	_ = PrepareNativeDNS("")
}

func TestAndroidNativeDNSStaleNilRetirementCannotDropNewOnOwner(t *testing.T) {
	defer closeNativeDNS()
	if err := PrepareNativeDNS(""); err != "" {
		t.Fatal(err)
	}
	androidDNS.Lock()
	old := androidDNS.epoch
	androidDNS.Unlock()
	if _, err := nativeDNSProxy(new(nativeDNSProbeProxy)); err != nil {
		t.Fatal(err)
	}
	retireNativeDNSSession(nil, old)
	androidDNS.Lock()
	retained := androidDNS.running
	androidDNS.Unlock()
	if !retained {
		t.Fatal("stale retirement cleared a new ON owner")
	}
	closeNativeDNS()
}

func TestAndroidNativeDNSDirectScopeNeverFallsBack(t *testing.T) {
	const config = `{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53","scope":"direct","network_token":"original-network-generation"}]}`
	if err := PrepareNativeDNS(config); err == "" {
		closeNativeDNS()
		t.Fatal("DIRECT scope accepted without a captured network controller")
	}
	controller := new(nativeDNSRejectNetwork)
	if err := RegisterNativeDNSController(controller); err != "" {
		t.Fatal(err)
	}
	if err := PrepareNativeDNS(config); err != "" {
		t.Fatal(err)
	}
	defer func() { closeNativeDNS(); _ = PrepareNativeDNS("") }()
	if err := RegisterNativeDNSController(new(nativeDNSRejectNetwork)); err == "" {
		t.Fatal("replaced the original network controller behind a prepared owner")
	}
	base := new(nativeDNSProbeProxy)
	p, err := nativeDNSProxy(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []M.Network{M.TCP, M.UDP} {
		if a := nativeDNSForwardAnswer(t, p, transport); a.Rcode != dns.RcodeServerFailure {
			t.Fatal("failed original network binding did not fail closed", a)
		}
	}
	if controller.calls.Load() != 2 || controller.invalid.Load() {
		t.Fatal("DIRECT sockets did not retain the exact original network generation")
	}
	if base.calls.Load() != 0 {
		t.Fatal("DIRECT binding failure fell back to the tunnel proxy")
	}
}

func TestAndroidNativeDNSRejectsScopeFlattening(t *testing.T) {
	for _, config := range []string{
		`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53","scope":"default"}]}`,
		`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53","scope":"tunnel","network_token":"other"}]}`,
		`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53","scope":"unavailable"}]}`,
		`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53","scope":"tunnel","sni":"resolver.test"}]}`,
	} {
		if err := PrepareNativeDNS(config); err == "" {
			closeNativeDNS()
			t.Fatal("flattened unknown DNS scope/security", config)
		}
	}
}

func TestAndroidNativeDNSAdmissionPinsGeneration(t *testing.T) {
	if err := PrepareNativeDNS(`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53"}]}`); err != "" {
		t.Fatal(err)
	}
	defer func() { closeNativeDNS(); _ = PrepareNativeDNS("") }()
	base := new(nativeDNSProbeProxy)
	if _, err := nativeDNSProxy(base); err != nil {
		t.Fatal(err)
	}
	// Simulate native device creation still pending: admission itself must
	// pin the owner; a post-start success callback is too late.
	if err := PrepareNativeDNS(""); err == "" {
		t.Fatal("replaced DNS generation during native device creation")
	}
	if err := CancelNativeDNS(); err == "" {
		t.Fatal("discarded an admitted partial native owner")
	}
	if _, err := nativeDNSProxy(base); err == nil {
		t.Fatal("admitted a replacement native engine before join")
	}
}

func (p *nativeDNSProbeProxy) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	p.calls.Add(1)
	return nil, nativeDNSDelegate
}

type nativeDNSForwardProxy struct {
	target             netip.AddrPort
	local              string
	tcpCalls, udpCalls atomic.Int32
}

func (p *nativeDNSForwardProxy) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	if m.DestinationAddrPort() != p.target || m.Network != M.TCP {
		return nil, nativeDNSDelegate
	}
	p.tcpCalls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp4", p.local)
}
func (p *nativeDNSForwardProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, errors.New("non-contextual DNS dial must never be used")
}
func (p *nativeDNSForwardProxy) DialUDPContext(ctx context.Context) (net.PacketConn, error) {
	p.udpCalls.Add(1)
	c, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	local, err := net.ResolveUDPAddr("udp4", p.local)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &nativeDNSForwardPacket{PacketConn: c, target: p.target, local: local}, nil
}

type nativeDNSForwardPacket struct {
	net.PacketConn
	target netip.AddrPort
	local  *net.UDPAddr
}

func (p *nativeDNSForwardPacket) WriteTo(b []byte, to net.Addr) (int, error) {
	if to.String() != p.target.String() {
		return 0, nativeDNSDelegate
	}
	return p.PacketConn.WriteTo(b, p.local)
}
func (p *nativeDNSForwardPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return n, from, err
	}
	if from.String() != p.local.String() {
		return 0, nil, nativeDNSDelegate
	}
	return n, net.UDPAddrFromAddrPort(p.target), nil
}

func nativeDNSForwardAnswer(t *testing.T, p proxy.Proxy, network M.Network) *dns.Msg {
	t.Helper()
	m := &M.Metadata{Network: network, DstIP: netip.MustParseAddr("198.19.255.1"), DstPort: 53}
	q := new(dns.Msg)
	q.SetQuestion("native-forward.test.", dns.TypeA)
	if network == M.TCP {
		c, err := p.DialContext(context.Background(), m)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
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
	c, err := p.DialUDP(m)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	b, _ := q.Pack()
	if _, err := c.WriteTo(b, m.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	b = make([]byte, 4096)
	n, from, err := c.ReadFrom(b)
	if err != nil || from.String() != m.DestinationAddress() {
		t.Fatal(from, err)
	}
	a := new(dns.Msg)
	if err := a.Unpack(b[:n]); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAndroidNativeDNSForwarding(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	ready := make(chan struct{}, 2)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		a := new(dns.Msg)
		a.SetReply(q)
		a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 0, 2, 9)}}
		_ = w.WriteMsg(a)
	})
	ts := &dns.Server{Listener: tcp, Handler: handler, NotifyStartedFunc: func() { ready <- struct{}{} }}
	us := &dns.Server{PacketConn: udp, Handler: handler, NotifyStartedFunc: func() { ready <- struct{}{} }}
	go ts.ActivateAndServe()
	go us.ActivateAndServe()
	<-ready
	<-ready
	defer ts.Shutdown()
	defer us.Shutdown()
	if err := PrepareNativeDNS(`{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"192.0.2.53:53"}]}`); err != "" {
		t.Fatal(err)
	}
	defer func() { closeNativeDNS(); _ = PrepareNativeDNS("") }()
	base := &nativeDNSForwardProxy{target: netip.MustParseAddrPort("192.0.2.53:53"), local: tcp.Addr().String()}
	p, err := nativeDNSProxy(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []M.Network{M.TCP, M.UDP} {
		a := nativeDNSForwardAnswer(t, p, transport)
		if a.Rcode != dns.RcodeSuccess || len(a.Answer) != 1 {
			t.Fatal(a)
		}
	}
	if base.tcpCalls.Load() != 1 || base.udpCalls.Load() != 1 {
		t.Fatal("native DNS changed transport")
	}
	quiesceNativeDNS()
	if a := nativeDNSForwardAnswer(t, p, M.TCP); a.Rcode != dns.RcodeServerFailure {
		t.Fatal(a)
	}
	if base.tcpCalls.Load() != 1 {
		t.Fatal("quiesce reopened forwarding")
	}
}
func (p *nativeDNSProbeProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	p.calls.Add(1)
	return nil, nativeDNSDelegate
}

func TestAndroidNativeDNSOwnerPolicy(t *testing.T) {
	if err := PrepareNativeDNS(""); err != "" {
		t.Fatal(err)
	}
	base := new(nativeDNSProbeProxy)
	p, err := nativeDNSProxy(base)
	if err != nil || p != base {
		t.Fatal("ON changed the native proxy", err)
	}
	if err := nativeDNSControl("tcp6", "[fd77::1]:443"); err != nil {
		t.Fatal("ON changed socket policy")
	}
	closeNativeDNS()
	const raw = `{"bindings":[{"endpoint":"198.19.255.1:53","upstream":"[fd77::2]:53"}]}`
	if err := PrepareNativeDNS(raw); err != "" {
		t.Fatal(err)
	}
	defer func() { closeNativeDNS(); _ = PrepareNativeDNS("") }()
	p, err = nativeDNSProxy(base)
	if err != nil {
		t.Fatal(err)
	}
	if nativeDNSControl("tcp", "[fd77::2]:53") == nil ||
		nativeDNSControl("udp6", "[::]:0") == nil ||
		nativeDNSControl("tcp", "resolver.test:53") == nil {
		t.Fatal("OFF authorized IPv6/unbound hostname control traffic")
	}
	if err := nativeDNSControl("udp4", "127.0.0.1:53"); err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddr("198.19.255.1")
	for _, transport := range []M.Network{M.TCP, M.UDP} {
		for _, kind := range []uint16{dns.TypeAAAA, dns.TypeA} {
			q := new(dns.Msg)
			q.SetQuestion("native-owner.test.", kind)
			m := &M.Metadata{Network: transport, DstIP: target, DstPort: 53}
			answer := new(dns.Msg)
			if transport == M.TCP {
				c, err := p.DialContext(context.Background(), m)
				if err != nil {
					t.Fatal(err)
				}
				_ = c.SetDeadline(time.Now().Add(time.Second))
				dc := &dns.Conn{Conn: c}
				if err := dc.WriteMsg(q); err != nil {
					t.Fatal(err)
				}
				answer, err = dc.ReadMsg()
				_ = c.Close()
				if err != nil {
					t.Fatal(err)
				}
			} else {
				c, err := p.DialUDP(m)
				if err != nil {
					t.Fatal(err)
				}
				_ = c.SetDeadline(time.Now().Add(time.Second))
				wire, _ := q.Pack()
				if _, err := c.WriteTo(wire, m.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 4096)
				n, from, err := c.ReadFrom(buffer)
				_ = c.Close()
				if err != nil || from.String() != m.DestinationAddress() {
					t.Fatal(from, err)
				}
				if err := answer.Unpack(buffer[:n]); err != nil {
					t.Fatal(err)
				}
			}
			want := dns.RcodeSuccess
			if kind == dns.TypeA {
				want = dns.RcodeServerFailure
			}
			if answer.Rcode != want || len(answer.Answer) != 0 {
				t.Fatal(answer)
			}
		}
	}
	if base.calls.Load() != 0 {
		t.Fatal("IPv6-only resolver reached the original proxy")
	}
	ordinary := &M.Metadata{DstIP: netip.MustParseAddr("192.0.2.8"), DstPort: 443}
	if _, err := p.DialContext(context.Background(), ordinary); !errors.Is(err, nativeDNSDelegate) {
		t.Fatal("ordinary IPv4 was not preserved")
	}
	literal := &M.Metadata{DstIP: netip.MustParseAddr("fd77::8"), DstPort: 443}
	if _, err := p.DialContext(context.Background(), literal); err == nil {
		t.Fatal("literal IPv6 passed")
	}
	if _, err := p.DialUDP(literal); err == nil {
		t.Fatal("UDP IPv6 passed")
	}
	if base.calls.Load() != 1 {
		t.Fatal("IPv6 delegation leak")
	}
	if CancelNativeDNS() == "" {
		t.Fatal("rollback discarded active native owner")
	}
	quiesceNativeDNS()
	closeNativeDNS()
	if nativeDNSControl("tcp", "[fd77::2]:53") == nil {
		t.Fatal("fence retired before Xray stop")
	}
}
