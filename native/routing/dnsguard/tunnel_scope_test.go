//go:build linux

package dnsguard

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestNativeTunnelSelectedResolverUsesExistingStackAndJoinedPortLease(t *testing.T) {
	remote, err := newPacketEndpoint(netip.MustParseAddr("10.8.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	udp, err := remote.listenUDP()
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := remote.listenTCP()
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	var requests atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		requests.Add(1)
		a := new(dns.Msg).SetReply(q)
		record, _ := dns.NewRR("native-tunnel.test. 60 IN A 198.51.100.2")
		a.Answer = []dns.RR{record}
		if q.Question[0].Name == "fragmented.native-tunnel.test." {
			chunks := make([]string, 20)
			for i := range chunks {
				chunks[i] = strings.Repeat("x", 200)
			}
			a.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name,
				Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: chunks}}
		}
		_ = w.WriteMsg(a)
	})
	servers := []*dns.Server{{PacketConn: udp, Handler: handler, UDPSize: 65535}, {Listener: tcp, Handler: handler}}
	var joined sync.WaitGroup
	for _, server := range servers {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		joined.Add(1)
		go func(s *dns.Server) { defer joined.Done(); _ = s.ActivateAndServe() }(server)
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("upstream did not start")
		}
	}
	defer func() {
		for _, server := range servers {
			_ = server.Shutdown()
		}
		joined.Wait()
	}()
	var releases, failures, engineWrites, fragments, ownedFragments atomic.Int32
	peer, clientStack, err := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	callbacks := packetCallbacks(&releases)
	callbacks.Dispatch, callbacks.Cancel = nil, nil
	callbacks.Failed = func() { failures.Add(1) }
	callbacks.Write = func(packet []byte) bool {
		_, err := peer.Write([][]byte{packet}, 0)
		return err == nil
	}
	server := nativedns.EncryptedServer{Address: netip.MustParseAddrPort("10.8.0.1:53")}
	session, err := NewTunnelPacketSession(context.Background(),
		netip.MustParseAddr("172.19.0.2"), netip.MustParseAddr("10.8.0.2"), 576, server,
		func(packet []byte) bool {
			engineWrites.Add(1)
			if len(packet) > 576 {
				t.Error("DNS engine packet exceeded original native tunnel MTU")
			}
			// Test peer represents the native engine, not another capture
			// endpoint: it accepts IP fragments through its one native input.
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), packet...)),
			})
			remote.link.InjectInbound(ipv4.ProtocolNumber, pkt)
			pkt.DecRef()
			return true
		}, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
		for {
			n, err := remote.Read(data, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				wire := data[0][:sizes[0]]
				original := append([]byte(nil), wire...)
				_, fragmented, ok := tunnelIPv4(wire)
				handled := session.FeedTunnel(wire)
				if !bytes.Equal(wire, original) {
					t.Error("native reader's borrowed packet changed")
				}
				if ok && fragmented {
					fragments.Add(1)
					if handled > 0 {
						ownedFragments.Add(1)
					} else if handled < 0 {
						t.Error("DNS fragment admission failed")
					}
				}
			}
		}
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
		for {
			n, err := peer.Read(data, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 && session.Feed(data[0][:sizes[0]]) < 0 {
				return
			}
		}
	}()
	defer func() { session.Close(); remote.Close(); peer.Close(); <-pumpDone; <-clientDone }()
	exchange, err := nativedns.SelectedResolver(server, session.tunnel.dial, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		q := new(dns.Msg)
		q.SetQuestion("native-tunnel.test.", dns.TypeA)
		a, err := exchange(context.Background(), network, q)
		if err != nil || a == nil || a.Id != q.Id || len(a.Answer) != 1 {
			t.Fatalf("%s selected native engine exchange: %v / %v", network, a, err)
		}
		session.tunnel.mu.Lock()
		leases := len(session.tunnel.leases)
		session.tunnel.mu.Unlock()
		if leases != 0 {
			t.Fatal("completed native DNS exchange retained a kernel port")
		}
	}
	if requests.Load() != 2 || engineWrites.Load() == 0 {
		t.Fatal("original selected upstream was not used")
	}
	for _, network := range []string{"udp", "tcp"} {
		before := engineWrites.Load()
		if a := query(t, clientStack, false, network, dns.TypeAAAA); a.Rcode != dns.RcodeSuccess ||
			len(a.Answer) != 0 || a.AuthenticatedData || engineWrites.Load() != before {
			t.Fatal("tunnel-scoped AAAA was not local NODATA")
		}
		if a := query(t, clientStack, false, network, dns.TypeA); a.Rcode != dns.RcodeSuccess || len(a.Answer) != 1 {
			t.Fatal("capture-to-native-engine A failed")
		}
	}
	if requests.Load() != 4 {
		t.Fatal("native capture path did not preserve selected DNS")
	}
	large := new(dns.Msg)
	large.SetQuestion("fragmented.native-tunnel.test.", dns.TypeTXT)
	large.SetEdns0(65535, true)
	large.Extra = append(large.Extra, &dns.TXT{Hdr: dns.RR_Header{Name: "padding.test.",
		Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{
		strings.Repeat("p", 200), strings.Repeat("p", 200), strings.Repeat("p", 200),
		strings.Repeat("p", 200), strings.Repeat("p", 200), strings.Repeat("p", 200)}})
	answer, err := exchange(context.Background(), "udp", large)
	if err != nil || answer == nil || len(answer.Answer) != 1 ||
		len(answer.Answer[0].(*dns.TXT).Txt) != 20 || fragments.Load() < 2 || ownedFragments.Load() == 0 {
		t.Fatalf("native MTU/fragment preservation: %v / %v / fragments=%d", answer, err, fragments.Load())
	}
	if _, err := session.tunnel.dial(context.Background(), "tcp4",
		netip.MustParseAddrPort("10.8.0.99:53")); err == nil {
		t.Fatal("tunnel dialer accepted resolver substitution")
	}
	if _, err := session.tunnel.dial(context.Background(), "udp6",
		server.Address); err == nil {
		t.Fatal("tunnel dialer accepted IPv6")
	}
	session.Close()
	if releases.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("retirement release=%d failure=%d", releases.Load(), failures.Load())
	}
}

func TestNativeTunnelFragmentOwnershipNeverCompletesDNSInKernelOrCapturesApplicationFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := &tunnelPacketScope{source: netip.MustParseAddr("10.8.0.2"),
		upstream: netip.MustParseAddrPort("10.8.0.1:53"),
		leases:   map[tunnelPort]context.Context{{6, 42053}: ctx}}
	makeFragment := func(first bool, port uint16) []byte {
		p := make([]byte, 28)
		p[0], p[8], p[9] = 0x45, 64, 6
		p[3], p[5] = 28, 77
		if first {
			p[6] = 0x20
		} else {
			p[7] = 1
		}
		copy(p[12:16], []byte{10, 8, 0, 1})
		copy(p[16:20], []byte{10, 8, 0, 2})
		p[21], p[22], p[23] = 53, byte(port>>8), byte(port)
		return p
	}
	last := makeFragment(false, 0)
	if mirror, consume := scope.incoming(last); !mirror || consume {
		t.Fatal("out-of-order unidentified fragment changed native application ownership")
	}
	first := makeFragment(true, 42053)
	if mirror, consume := scope.incoming(first); !mirror || !consume {
		t.Fatal("kernel could reassemble/reset the private DNS TCP flow")
	}
	if mirror, consume := scope.incoming(last); !mirror || !consume {
		t.Fatal("known DNS fragments lost their exclusive ownership")
	}
	cancel()
	if mirror, consume := scope.incoming(last); mirror || !consume {
		t.Fatal("cancelled private flow forwarded or leaked a known fragment")
	}
	application := makeFragment(true, 42054)
	original := append([]byte(nil), application...)
	if mirror, consume := scope.incoming(application); mirror || consume || !bytes.Equal(original, application) {
		t.Fatal("application-owned first fragment was captured or changed")
	}
	if mirror, consume := scope.incoming(last); mirror || consume {
		t.Fatal("stale DNS fragment ID captured a later application flow")
	}
}

func TestNativeTunnelUnownedInputDoesNotAllocateOrMutate(t *testing.T) {
	var releases atomic.Int32
	callbacks := packetCallbacks(&releases)
	callbacks.Dispatch, callbacks.Cancel = nil, nil
	session, err := NewTunnelPacketSession(context.Background(),
		netip.MustParseAddr("198.19.255.1"), netip.MustParseAddr("10.8.0.2"), 1500,
		nativedns.EncryptedServer{Address: netip.MustParseAddrPort("10.8.0.1:53")},
		func([]byte) bool { t.Error("unowned application packet reached engine"); return false }, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	packet := []byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0,
		10, 8, 0, 1, 10, 8, 0, 2, 0, 53, 0xa4, 0x4e, 0, 8, 0, 0}
	original := append([]byte(nil), packet...)
	allocations := testing.AllocsPerRun(1000, func() {
		if session.FeedTunnel(packet) != 0 {
			t.Error("unowned native application flow was captured")
		}
	})
	if allocations != 0 || !bytes.Equal(packet, original) {
		t.Fatalf("unowned native path allocations=%g or borrowed bytes changed", allocations)
	}
	t.Logf("unowned native application input: %g allocations/call, 1000 measured calls", allocations)
}

func TestNativeTunnelResumeAndRetirementJoinPendingEngineWriter(t *testing.T) {
	var releases, failures atomic.Int32
	entered, allowReturn := make(chan struct{}), make(chan struct{})
	var enteredOnce, unblock sync.Once
	callbacks := packetCallbacks(&releases)
	callbacks.Dispatch, callbacks.Cancel = nil, nil
	callbacks.Failed = func() { failures.Add(1) }
	selected := nativedns.EncryptedServer{Address: netip.MustParseAddrPort("10.8.0.1:53")}
	session, err := NewTunnelPacketSession(context.Background(),
		netip.MustParseAddr("198.19.255.1"), netip.MustParseAddr("10.8.0.2"), 1280, selected,
		func([]byte) bool {
			enteredOnce.Do(func() { close(entered) })
			<-allowReturn
			return false // A cancelled native engine must not revive/fail the owner.
		}, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock.Do(func() { close(allowReturn) }); session.Close() })
	conn, err := session.tunnel.dial(session.scopeCtx, "udp4", selected.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("pending native DNS output")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("existing stack output did not reach engine callback")
	}
	// The resolver itself has returned, but its native-engine output callback
	// is still borrowed. Resume must not use just the forwarding counter.
	conn.Close()
	session.Quiesce()
	if session.Resume() {
		t.Fatal("new scope overlapped a previous native engine callback")
	}
	joined := make(chan struct{})
	go func() { session.Close(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("native host retired before the engine writer joined")
	case <-time.After(25 * time.Millisecond):
	}
	if releases.Load() != 0 {
		t.Fatal("pending engine callback lost native ownership")
	}
	unblock.Do(func() { close(allowReturn) })
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("native output writer did not join")
	}
	if releases.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("cancelled engine retirement release=%d failure=%d", releases.Load(), failures.Load())
	}
}
