package dnsguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/miekg/dns"
)

func packetCallbacks(releases *atomic.Int32) PacketCallbacks {
	return PacketCallbacks{
		Write:    func([]byte) bool { return true },
		Dispatch: func(NativeRequest) error { return errors.New("no selected scope") },
		Cancel:   func(uint64) {}, Failed: func() {}, Release: func() { releases.Add(1) },
	}
}

func TestPacketSessionFailedPreparationReleasesHostExactlyOnce(t *testing.T) {
	for _, missing := range []string{"write", "dispatch", "cancel", "failure", "address", "context"} {
		t.Run(missing, func(t *testing.T) {
			var releases atomic.Int32
			callbacks := packetCallbacks(&releases)
			address := netip.MustParseAddr("172.19.0.2")
			parent := context.Background()
			switch missing {
			case "write":
				callbacks.Write = nil
			case "dispatch":
				callbacks.Dispatch = nil
			case "cancel":
				callbacks.Cancel = nil
			case "failure":
				callbacks.Failed = nil
			case "address":
				address = netip.Addr{}
			case "context":
				parent = nil
			}
			session, err := NewPacketSession(parent, address, callbacks)
			if err == nil || session != nil || releases.Load() != 1 {
				t.Fatalf("invalid host ownership: session=%v err=%v releases=%d", session, err, releases.Load())
			}
		})
	}
}

func TestPacketSessionIntentionalCloseNeverReportsFailure(t *testing.T) {
	var releases, failures atomic.Int32
	callbacks := packetCallbacks(&releases)
	callbacks.Failed = func() { failures.Add(1) }
	session, err := NewPacketSession(context.Background(), netip.MustParseAddr("172.19.0.2"), callbacks)
	if err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for i := 0; i < 8; i++ {
		joined.Add(1)
		go func() { defer joined.Done(); session.Close() }()
	}
	joined.Wait()
	if releases.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("releases=%d failures=%d", releases.Load(), failures.Load())
	}
	if session.Feed([]byte{0x45}) != -1 || session.Reject(1) || session.Complete(1, make([]byte, 12)) {
		t.Fatal("retired session admitted packet/completion")
	}
}

func TestPacketSessionFailureCallbackJoinsBeforeHostRelease(t *testing.T) {
	var releases, failures atomic.Int32
	started, allowReturn := make(chan struct{}), make(chan struct{})
	callbacks := packetCallbacks(&releases)
	callbacks.Failed = func() { failures.Add(1); close(started); <-allowReturn }
	session, err := NewPacketSession(context.Background(), netip.MustParseAddr("172.19.0.2"), callbacks)
	if err != nil {
		t.Fatal(err)
	}
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(allowReturn) }); session.Close() })
	// Terminate the real frontend without marking the session as intentionally
	// stopping. Its output reader must observe and report exactly one failure.
	session.frontend.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("frontend failure was not delivered")
	}
	if session.Feed([]byte{0x45}) != -1 {
		t.Fatal("failed generation still admits native input")
	}
	closed := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() { session.Close(); closed <- struct{}{} }()
	}
	select {
	case <-closed:
		t.Fatal("close returned before callback joined")
	case <-time.After(30 * time.Millisecond):
	}
	if releases.Load() != 0 {
		t.Fatal("host released during in-flight failure callback")
	}
	unblock.Do(func() { close(allowReturn) })
	for i := 0; i < 2; i++ {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("idempotent close did not join")
		}
	}
	if failures.Load() != 1 || releases.Load() != 1 {
		t.Fatalf("failures=%d releases=%d", failures.Load(), releases.Load())
	}
}

func TestPacketSessionNativeUDPAndTCPKeepSelectedExchange(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			peer, stack, err := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1280)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			var releases, dispatches, failures atomic.Int32
			callbacks := packetCallbacks(&releases)
			callbacks.Failed = func() { failures.Add(1) }
			callbacks.Write = func(packet []byte) bool {
				_, err := peer.Write([][]byte{packet}, 0)
				return err == nil
			}
			var session *PacketSession
			callbacks.Dispatch = func(request NativeRequest) error {
				dispatches.Add(1)
				if request.Network != network {
					return errors.New("native transport changed")
				}
				q := new(dns.Msg)
				if err := q.Unpack(request.Wire); err != nil {
					return err
				}
				if !q.AuthenticatedData || q.IsEdns0() == nil || !q.IsEdns0().Do() {
					return errors.New("native DNS authentication/request flags changed")
				}
				answer := new(dns.Msg).SetReply(q)
				record, err := dns.NewRR("managed.example. 60 IN A 198.51.100.2")
				if err != nil {
					return err
				}
				answer.Answer = []dns.RR{record}
				wire, err := answer.Pack()
				if err != nil {
					return err
				}
				if !session.Complete(request.ID, wire) {
					return errors.New("native response rejected")
				}
				return nil
			}
			session, err = NewPacketSession(context.Background(), netip.MustParseAddr("172.19.0.2"), callbacks)
			if err != nil {
				t.Fatal(err)
			}
			pumpDone := make(chan struct{})
			go func() {
				defer close(pumpDone)
				data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
				for {
					count, err := peer.Read(data, sizes, 0)
					if err != nil {
						return
					}
					if count > 0 && session.Feed(data[0][:sizes[0]]) < 0 {
						return
					}
				}
			}()
			t.Cleanup(func() {
				session.Close()
				peer.Close()
				select {
				case <-pumpDone:
				case <-time.After(time.Second):
					t.Error("existing native reader did not join")
				}
			})
			if a := query(t, stack, false, network, dns.TypeAAAA); a.Rcode != dns.RcodeSuccess ||
				len(a.Answer) != 0 || a.AuthenticatedData || dispatches.Load() != 0 {
				t.Fatal("AAAA did not remain local unauthenticated NODATA")
			}
			if a := query(t, stack, false, network, dns.TypeA); a.Rcode != dns.RcodeSuccess ||
				len(a.Answer) != 1 || dispatches.Load() != 1 {
				t.Fatal("native scoped A exchange failed")
			}
			session.Close()
			if failures.Load() != 0 || releases.Load() != 1 {
				t.Fatalf("failure=%d release=%d", failures.Load(), releases.Load())
			}
		})
	}
}
