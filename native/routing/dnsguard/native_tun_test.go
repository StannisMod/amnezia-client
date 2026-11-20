package dnsguard

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/miekg/dns"
)

type nativeTestTUN struct {
	tun.Device
	fromOS, toOS chan []byte
	done         chan struct{}
	once         sync.Once
}

func newNativeTestTUN() *nativeTestTUN {
	return &nativeTestTUN{fromOS: make(chan []byte, 8), toOS: make(chan []byte, 8), done: make(chan struct{})}
}

func (n *nativeTestTUN) Read(data [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-n.done:
		return 0, io.EOF
	case packet := <-n.fromOS:
		sizes[0] = copy(data[0][offset:], packet)
		return 1, nil
	}
}

func (n *nativeTestTUN) Write(data [][]byte, offset int) (int, error) {
	for _, packet := range data {
		select {
		case <-n.done:
			return 0, io.EOF
		case n.toOS <- bytes.Clone(packet[offset:]):
		}
	}
	return len(data), nil
}

func (n *nativeTestTUN) Close() error { n.once.Do(func() { close(n.done) }); return nil }

func TestNativeTUNPreservesNonDNSPacketsAndOffset(t *testing.T) {
	base := newNativeTestTUN()
	wrapped, err := WrapNativeTUN(context.Background(), base, netip.MustParseAddr("172.19.0.2"),
		func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
			t.Error("non-DNS native packet reached the resolver")
			return nil, io.EOF
		})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	// Non-TCP traffic must not be turned into a flow proxy. An opaque native
	// packet and its TUN headroom remain byte-for-byte unchanged.
	packet := bytes.Repeat([]byte{0x55}, 80)
	packet[0] = 0x45
	copy(packet[16:20], []byte{198, 51, 100, 2})
	base.fromOS <- packet
	buffer := bytes.Repeat([]byte{0xaa}, 256)
	sizes := make([]int, 1)
	n, err := wrapped.Read([][]byte{buffer}, sizes, 16)
	if err != nil || n != 1 || sizes[0] != len(packet) ||
		!bytes.Equal(buffer[:16], bytes.Repeat([]byte{0xaa}, 16)) ||
		!bytes.Equal(buffer[16:16+sizes[0]], packet) {
		t.Fatal("native packet or headroom was changed")
	}
	if _, err := wrapped.Write([][]byte{buffer[:16+sizes[0]]}, 16); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(<-base.toOS, packet) {
		t.Fatal("native return packet was changed")
	}
}

func TestNativeTUNManagedDNSDoesNotReachNativeBackend(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			base := newNativeTestTUN()
			var upstream atomic.Int32
			wrapped, err := WrapNativeTUN(context.Background(), base, netip.MustParseAddr("172.19.0.2"),
				func(context.Context, string, *dns.Msg) (*dns.Msg, error) {
					upstream.Add(1)
					return nil, io.EOF
				})
			if err != nil {
				t.Fatal(err)
			}
			peer, stack, err := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1280)
			if err != nil {
				wrapped.Close()
				t.Fatal(err)
			}
			var nativePackets atomic.Int32
			done := make(chan struct{}, 3)
			go func() {
				defer func() { done <- struct{}{} }()
				data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
				for {
					n, err := peer.Read(data, sizes, 0)
					if err != nil {
						return
					}
					if n > 0 {
						select {
						case base.fromOS <- bytes.Clone(data[0][:sizes[0]]):
						case <-base.done:
							return
						}
					}
				}
			}()
			go func() {
				defer func() { done <- struct{}{} }()
				for {
					select {
					case packet := <-base.toOS:
						if _, err := peer.Write([][]byte{packet}, 0); err != nil {
							return
						}
					case <-base.done:
						return
					}
				}
			}()
			go func() {
				defer func() { done <- struct{}{} }()
				data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
				for {
					count, err := wrapped.Read(data, sizes, 16)
					nativePackets.Add(int32(count))
					if err != nil {
						return
					}
				}
			}()
			t.Cleanup(func() {
				wrapped.Close()
				peer.Close()
				for i := 0; i < 3; i++ {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("native DNS adapter packet worker leaked")
					}
				}
			})
			answer := query(t, stack, false, transport, dns.TypeAAAA)
			if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 ||
				nativePackets.Load() != 0 || upstream.Load() != 0 {
				t.Fatal("AAAA escaped managed-DNS frontend or was not NODATA")
			}
		})
	}
}
