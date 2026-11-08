//go:build linux && !android

package engine

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

var stabilityDomainMoves sync.Map

// Called only on the fixture's locked peer-netns thread. All public bootstrap
// and endpoint addresses are synthetic local aliases; no Internet DNS is used.
func stabilityDomainFrontdoors(t *testing.T, backend netip.AddrPort) netip.AddrPort {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("domain fixture ip %v: %v %s", args, e, b)
		}
	}
	for _, address := range []string{"203.0.113.4/32", "203.0.113.5/32", "1.1.1.1/32"} {
		run("addr", "add", address, "dev", "lo")
	}
	var active atomic.Int32
	var lookupCount atomic.Int32
	stabilityDomainMoves.Store(t.Name(), &active)
	t.Cleanup(func() {
		stabilityDomainMoves.Delete(t.Name())
		if lookupCount.Load() == 0 {
			t.Error("native endpoint owner never queried fresh control DNS")
		}
	})
	pc, e := net.ListenPacket("udp4", "1.1.1.1:53")
	if e != nil {
		t.Fatal(e)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		if len(q.Question) != 1 || q.Question[0].Name != "endpoint.test." {
			t.Error("application name escaped into endpoint control DNS")
			reply.Rcode = dns.RcodeNameError
		} else {
			lookupCount.Add(1)
			if q.Question[0].Qtype == dns.TypeA {
				address := "203.0.113.4"
				if active.Load() == 1 {
					address = "203.0.113.5"
				}
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "endpoint.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(address)}}
			}
		}
		w.WriteMsg(reply)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go server.ActivateAndServe()
	<-ready
	t.Cleanup(func() { server.Shutdown() })
	frontPort := uint16(0)
	for index, address := range []string{"203.0.113.4", "203.0.113.5"} {
		listener, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(address), frontPort)))
		if e != nil {
			t.Fatal(e)
		}
		frontPort = listener.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		upstream, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			listener.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { listener.Close(); upstream.Close() })
		var mu sync.Mutex
		var client netip.AddrPort
		go func(index int) {
			data := make([]byte, 65535)
			for {
				n, source, e := listener.ReadFromUDPAddrPort(data)
				if e != nil {
					return
				}
				if active.Load() != int32(index) {
					continue
				}
				mu.Lock()
				client = source
				mu.Unlock()
				upstream.WriteToUDPAddrPort(data[:n], netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), backend.Port()))
			}
		}(index)
		go func(index int) {
			data := make([]byte, 65535)
			for {
				n, _, e := upstream.ReadFromUDPAddrPort(data)
				if e != nil {
					return
				}
				if active.Load() != int32(index) {
					continue
				}
				mu.Lock()
				target := client
				mu.Unlock()
				if target.IsValid() {
					listener.WriteToUDPAddrPort(data[:n], target)
				}
			}
		}(index)
	}
	return netip.AddrPortFrom(netip.MustParseAddr("203.0.113.4"), frontPort)
}
func stabilityNativeDomainMove(t *testing.T) {
	t.Helper()
	if os.Getenv("AMNEZIA_STABILITY_LAB") != "isolated-container" && os.Getenv("AMNEZIA_STABILITY_LAB") != "isolated-namespace" {
		t.Fatal("domain move requires isolated native fixture")
	}
	move, ok := stabilityDomainMoves.Load(t.Name())
	if !ok {
		t.Fatal("missing domain peer fixture")
	}
	move.(*atomic.Int32).Store(1)
}

func stabilityNativeDomainEndpoint(t *testing.T, endpoint netip.AddrPort) netip.AddrPort {
	t.Helper()
	state, ok := stabilityDomainMoves.Load(t.Name())
	if !ok {
		t.Fatal("missing native DNS fixture")
	}
	address := "203.0.113.4"
	if state.(*atomic.Int32).Load() == 1 {
		address = "203.0.113.5"
	}
	return netip.AddrPortFrom(netip.MustParseAddr(address), endpoint.Port())
}
