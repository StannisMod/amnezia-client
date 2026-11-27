package dnsguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// This is a feasibility measurement, NOT a production adapter or Android
// acceptance. It proves that the existing DNS capture stack can also originate
// a DNS-only native-engine flow without adding a stack or a TUN reader.
func TestDNSOnlyExistingStackTunnelExchange(t *testing.T) {
	source := netip.MustParseAddr("10.8.0.2")
	upstream := netip.MustParseAddr("10.8.0.1")
	local, err := newPacketEndpoint(netip.MustParseAddr("198.19.255.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	remote, err := newPacketEndpoint(upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if err := local.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(source.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	udp, err := remote.listenUDP()
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := remote.listenTCP()
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		a := new(dns.Msg)
		a.SetReply(q)
		a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name,
			Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(198, 51, 100, 2)}}
		_ = w.WriteMsg(a)
	})
	servers := []*dns.Server{{PacketConn: udp, Handler: handler}, {Listener: tcp, Handler: handler}}
	var joined sync.WaitGroup
	for _, server := range servers {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		joined.Add(1)
		go func(s *dns.Server) { defer joined.Done(); _ = s.ActivateAndServe() }(server)
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("test upstream did not start")
		}
	}
	defer func() {
		for _, server := range servers {
			_ = server.Shutdown()
		}
		joined.Wait()
	}()
	var pumps sync.WaitGroup
	// The real adapter must classify the exact leased tuple here and invoke
	// its existing engine on the engine thread. Direct private-stack injection
	// below is ONLY a test peer, not permission to feed application packets.
	pump := func(from, to *packetEndpoint) {
		defer pumps.Done()
		data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
		for {
			n, err := from.Read(data, sizes, 0)
			if err != nil {
				return
			}
			if n == 1 {
				wire := append([]byte(nil), data[0][:sizes[0]]...)
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
				to.link.InjectInbound(ipv4.ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	}
	pumps.Add(2)
	go pump(local, remote)
	go pump(remote, local)
	defer func() { local.Close(); remote.Close(); pumps.Wait() }()
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			bound := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(source.AsSlice()), Port: 42053}
			target := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(upstream.AsSlice()), Port: 53}
			var conn net.Conn
			var err error
			if transport == "udp" {
				conn, err = gonet.DialUDP(local.stack, &bound, &target, ipv4.ProtocolNumber)
			} else {
				conn, err = gonet.DialTCPWithBind(ctx, local.stack, bound, target, ipv4.ProtocolNumber)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			wire := &dns.Conn{Conn: conn}
			q := new(dns.Msg)
			q.SetQuestion("native-engine.test.", dns.TypeA)
			if err := wire.WriteMsg(q); err != nil {
				t.Fatal(err)
			}
			a, err := wire.ReadMsg()
			if err != nil || a.Id != q.Id || len(a.Answer) != 1 {
				t.Fatalf("same-stack tunnel DNS response: %v / %v", a, err)
			}
			if conn.LocalAddr().String() != "10.8.0.2:42053" {
				t.Fatal("original native tunnel source changed")
			}
		})
	}
}
