package awg

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// Hide the optional native route watcher: these peers use loopback only.
type recoveryServerBind struct{ conn.Bind }

func TestBindKeepsControlPlaneTargetAndReceiveFilter(t *testing.T) {
	old, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	current, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	var lc net.ListenConfig
	remote := netip.MustParseAddrPort(current.LocalAddr().String())
	b := &packetBind{ctx: context.Background(), listen: lc.ListenPacket, endpoint: remote}
	receive, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	retired := endpoint(netip.MustParseAddrPort(old.LocalAddr().String()))
	if err = b.Send([][]byte{[]byte("current target")}, retired); err != nil {
		t.Fatal(err)
	}
	current.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, _, err := current.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "current target" {
		t.Fatal("revived retired endpoint", err)
	}
	local := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
	old.WriteTo([]byte("retired source"), local)
	current.WriteTo([]byte("current source"), local)
	done := make(chan error, 1)
	go func() {
		packets := [][]byte{make([]byte, 128)}
		sizes := make([]int, 1)
		peers := make([]conn.Endpoint, 1)
		_, err := receive[0](packets, sizes, peers)
		if err == nil && (string(packets[0][:sizes[0]]) != "current source" || peers[0].DstToString() != remote.String()) {
			err = errors.New("retired source passed endpoint filter")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("current source not received")
	}
}

// The front endpoint stays fixed when rotateNAT replaces the server-facing
// socket. A second relay lets the test move the endpoint/family too, while
// retaining the very same remote device and TCP stack.
type recoveryRelay struct {
	front  net.PacketConn
	mu     sync.Mutex
	back   net.PacketConn
	client net.Addr
	peer   net.Addr
	wg     sync.WaitGroup
}

func newRecoveryRelay(t *testing.T, network, address string, peer net.Addr) *recoveryRelay {
	t.Helper()
	front, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	r := &recoveryRelay{front: front, peer: peer}
	t.Cleanup(r.close)
	r.rotateNAT(t)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := r.front.ReadFrom(buf)
			if err != nil {
				return
			}
			r.mu.Lock()
			r.client = from
			back := r.back
			r.mu.Unlock()
			back.WriteTo(buf[:n], r.peer)
		}
	}()
	return r
}

func (r *recoveryRelay) rotateNAT(t *testing.T) {
	t.Helper()
	back, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	old := r.back
	r.back = back
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			if from.String() != r.peer.String() {
				continue
			}
			r.mu.Lock()
			current, client := r.back == back, r.client
			r.mu.Unlock()
			if current && client != nil {
				r.front.WriteTo(buf[:n], client)
			}
		}
	}()
}
func (r *recoveryRelay) endpoint() netip.AddrPort {
	return netip.MustParseAddrPort(r.front.LocalAddr().String())
}
func (r *recoveryRelay) close() {
	r.front.Close()
	r.mu.Lock()
	back := r.back
	r.mu.Unlock()
	if back != nil {
		back.Close()
	}
	r.wg.Wait()
}

func recoveryIdentity(t *testing.T, c *Transport) [32]byte {
	t.Helper()
	raw, err := c.device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var identity []string
	for _, line := range strings.Split(raw, "\n") {
		for _, prefix := range []string{"private_key=", "public_key=", "preshared_key=", "allowed_ip=", "persistent_keepalive_interval="} {
			if strings.HasPrefix(line, prefix) {
				identity = append(identity, line)
			}
		}
	}
	return sha256.Sum256([]byte(strings.Join(identity, "\n")))
}

func TestRefreshUnderlayPreservesTCPThroughNATAndEndpointMove(t *testing.T) {
	for _, standard := range []bool{false, true} {
		for _, innerV6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("standard=%t/innerIPv6=%t", standard, innerV6), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				clientIP, serverIP, mask := "10.77.0.1", "10.77.0.2", "/32"
				if innerV6 {
					clientIP, serverIP, mask = "fd77::1", "fd77::2", "/128"
				}
				aPriv, aPub := keypair(t)
				bPriv, bPub := keypair(t)
				params := map[string]string(nil)
				if !standard {
					params = map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
				}
				packet, stack, err := NewFlowTUN([]netip.Addr{netip.MustParseAddr(serverIP)}, 1280)
				if err != nil {
					t.Fatal(err)
				}
				peerConfig := Config{Address: []netip.Addr{netip.MustParseAddr(serverIP)}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + mask)}, Parameters: params}
				ipc, err := peerConfig.uapi()
				if err != nil {
					t.Fatal(err)
				}
				peer, err := NewConfiguredDevice(packet, recoveryServerBind{conn.NewStdNetBind()}, ipc)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				state, err := peer.IpcGet()
				if err != nil {
					t.Fatal(err)
				}
				var port uint16
				for _, line := range strings.Split(state, "\n") {
					if strings.HasPrefix(line, "listen_port=") {
						fmt.Sscanf(line, "listen_port=%d", &port)
					}
				}
				if port == 0 {
					t.Fatal("peer has no UDP port")
				}
				peerAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
				first := newRecoveryRelay(t, "udp4", "127.0.0.1:0", peerAddr)
				second := newRecoveryRelay(t, "udp6", "[::1]:0", peerAddr)
				var lc net.ListenConfig
				var failNext atomic.Bool
				var opens atomic.Int32
				client, err := New(ctx, Config{Address: []netip.Addr{netip.MustParseAddr(clientIP)}, PrivateKey: aPriv, PublicKey: bPub, Endpoint: first.endpoint(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(serverIP + mask)}, Parameters: params}, func(c context.Context, n, a string) (net.PacketConn, error) {
					opens.Add(1)
					if failNext.Swap(false) {
						return nil, errors.New("injected socket failure")
					}
					return lc.ListenPacket(c, n, a)
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				originalStack := client.Net
				identity := recoveryIdentity(t, client)
				listener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 8080))
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				var accepts atomic.Int32
				go func() {
					for {
						c, e := listener.Accept()
						if e != nil {
							return
						}
						accepts.Add(1)
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
				stream, err := client.DialContext(ctx, "tcp", net.JoinHostPort(serverIP, "8080"))
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(15 * time.Second))
				exchange := func(step string) {
					t.Helper()
					if _, e := io.WriteString(stream, step); e != nil {
						t.Fatal(step, e)
					}
					got := make([]byte, len(step))
					if _, e := io.ReadFull(stream, got); e != nil || string(got) != step {
						t.Fatal(step, "TCP did not resume", e)
					}
					if accepts.Load() != 1 || client.Net != originalStack || recoveryIdentity(t, client) != identity {
						t.Fatal("recovery replaced established state")
					}
				}
				exchange("initial")
				before, _ := client.Stats()
				first.rotateNAT(t)
				if err = client.RefreshUnderlay(netip.AddrPort{}); err != nil {
					t.Fatal(err)
				}
				exchange("new NAT source")
				failNext.Store(true)
				if err = client.RefreshUnderlay(netip.AddrPort{}); err == nil {
					t.Fatal("missing injected failure")
				}
				if err = client.RefreshUnderlay(netip.AddrPort{}); err != nil {
					t.Fatal(err)
				}
				exchange("same TCP after failed reopen")
				if err = client.RefreshUnderlay(second.endpoint()); err != nil {
					t.Fatal(err)
				}
				first.front.Close() // The retired endpoint is no longer reachable.
				exchange("outer IPv6 endpoint")
				after, _ := client.Stats()
				if after.TXBytes < before.TXBytes || after.RXBytes < before.RXBytes {
					t.Fatal("recovery reset counters")
				}
				count := opens.Load()
				for _, bad := range []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("0.0.0.0:9"), netip.MustParseAddrPort("224.0.0.1:9"), netip.AddrPortFrom(netip.Addr{}, 9)} {
					if err = client.RefreshUnderlay(bad); err == nil {
						t.Fatal("accepted invalid target")
					}
				}
				if opens.Load() != count {
					t.Fatal("invalid request disturbed live socket")
				}
				exchange("invalid targets leave TCP intact")
			})
		}
	}
}

// Fault-inject a send buffer that only drains on its deadline or explicit
// release. The real device network lock is held by SendBuffers in this test.
type stalledRecoverySocket struct {
	net.PacketConn
	mu          sync.Mutex
	deadline    time.Time
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (s *stalledRecoverySocket) SetWriteDeadline(d time.Time) error {
	s.mu.Lock()
	s.deadline = d
	s.mu.Unlock()
	return s.PacketConn.SetWriteDeadline(d)
}
func (s *stalledRecoverySocket) unblock()     { s.releaseOnce.Do(func() { close(s.release) }) }
func (s *stalledRecoverySocket) Close() error { s.unblock(); return s.PacketConn.Close() }
func (s *stalledRecoverySocket) WriteTo(p []byte, a net.Addr) (int, error) {
	s.once.Do(func() { close(s.entered) })
	s.mu.Lock()
	d := s.deadline
	s.mu.Unlock()
	var timeout <-chan time.Time
	if !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-s.release:
		return s.PacketConn.WriteTo(p, a)
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func TestRefreshUnderlayCannotBeWedgedByBlockedSend(t *testing.T) {
	priv, _ := keypair(t)
	_, pub := keypair(t)
	var lc net.ListenConfig
	var first *stalledRecoverySocket
	c, err := New(context.Background(), Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: priv, PublicKey: pub, Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, func(ctx context.Context, n, a string) (net.PacketConn, error) {
		pc, e := lc.ListenPacket(ctx, n, a)
		if e != nil {
			return nil, e
		}
		if first == nil {
			first = &stalledRecoverySocket{PacketConn: pc, entered: make(chan struct{}), release: make(chan struct{})}
			return first, nil
		}
		return pc, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer first.unblock()
	peer := c.device.LookupPeer(c.peerKey)
	blocked := make(chan error, 1)
	go func() { blocked <- peer.SendBuffers([][]byte{{0}}) }()
	select {
	case <-first.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("send never entered")
	}
	queued := make(chan error, 10)
	for range 10 {
		go func() { queued <- peer.SendBuffers([][]byte{{0}}) }()
	}
	for range 10 {
		select {
		case e := <-queued:
			if e == nil {
				t.Fatal("blocked socket accepted queued send")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("send queue holds device read locks")
		}
	}
	done := make(chan error, 1)
	go func() { done <- c.RefreshUnderlay(netip.AddrPort{}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("refresh blocked behind UDP write")
	}
	select {
	case err := <-blocked:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("send did not honor deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("old sender leaked")
	}
	c.Close()
	if !errors.Is(c.RefreshUnderlay(netip.AddrPort{}), net.ErrClosed) {
		t.Fatal("closed transport reopened")
	}
}
