package engine

// This opt-in reproduction uses the production router/runtime and real encrypted
// AWG/WG over local UDP. It installs no OS TUN, routes, DNS or firewall rules.
import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/websocket"
)

type stabilityLink struct {
	blackhole atomic.Bool
	impaired  atomic.Bool
	dropped   atomic.Uint64
	mu        sync.Mutex
	rng       *rand.Rand
}

func (l *stabilityLink) drop() bool {
	if l.blackhole.Load() {
		l.dropped.Add(1)
		return true
	}
	if !l.impaired.Load() {
		return false
	}
	l.mu.Lock()
	drop := l.rng.Intn(100) < 10
	delay := time.Duration(5+l.rng.Intn(16)) * time.Millisecond
	l.mu.Unlock()
	if drop {
		l.dropped.Add(1)
	} else {
		time.Sleep(delay)
	}
	return drop
}

type stabilityPacket struct {
	net.PacketConn
	link *stabilityLink
}

func (p *stabilityPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	if p.link.drop() {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, a)
}
func (p *stabilityPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := p.PacketConn.ReadFrom(b)
		if e != nil || !p.link.drop() {
			return n, a, e
		}
	}
}

type stabilityListener struct {
	net.Listener
	accepts     atomic.Int32
	mu          sync.Mutex
	connections []net.Conn
}

func (l *stabilityListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e == nil {
		l.accepts.Add(1)
		l.mu.Lock()
		l.connections = append(l.connections, c)
		l.mu.Unlock()
	}
	return c, e
}

func (l *stabilityListener) closeConnections() {
	l.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.connections {
		c.Close()
	}
	l.connections = nil
}

func TestConnectionStabilityReproduction(t *testing.T) {
	if os.Getenv("AMNEZIA_STABILITY_REPRO") != "1" {
		t.Skip("set AMNEZIA_STABILITY_REPRO=1; roughly two minutes, no host network changes")
	}
	outages := [][]time.Duration{{time.Second}, {3 * time.Second}, {10 * time.Second}, {30 * time.Second}}
	if os.Getenv("AMNEZIA_STABILITY_SEQUENCE") == "1" {
		outages = [][]time.Duration{{time.Second, 3 * time.Second, 10 * time.Second, 30 * time.Second}}
	}
	if os.Getenv("AMNEZIA_STABILITY_NO_OUTAGES") == "1" {
		outages = [][]time.Duration{nil}
	}
	for _, protocol := range []string{"amneziawg", "amnezia-wireguard"} {
		for _, family := range []string{"IPv4", "IPv6"} {
			for _, pauses := range outages {
				t.Run(fmt.Sprintf("%s/%s/%v", protocol, family, pauses), func(t *testing.T) {
					if os.Getenv("AMNEZIA_STABILITY_KERNEL_PEER") != "1" {
						t.Parallel()
					}
					reproduceStability(t, protocol, family, pauses)
				})
			}
		}
	}
}

func reproduceStability(t *testing.T, protocol, family string, pauses []time.Duration) {
	lifetime := 240 * time.Second
	if os.Getenv("AMNEZIA_CHAOS_PROFILE") != "" {
		lifetime = max(lifetime, stabilityChaosSeconds("AMNEZIA_CHAOS_SECONDS", 3)+stabilityChaosSeconds("AMNEZIA_CHAOS_RECOVERY_SECONDS", 30)+60*time.Second)
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	defer cancel()
	clientIP, serverIP, mask := "10.77.0.1", "10.77.0.2", "/32"
	if family == "IPv6" {
		clientIP, serverIP, mask = "fd77::1", "fd77::2", "/128"
	}
	aPriv, aPub := keys(t)
	bPriv, bPub := keys(t)
	reserved, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	clientPort := uint16(reserved.LocalAddr().(*net.UDPAddr).Port)
	reserved.Close()
	params := map[string]string(nil)
	if protocol == "amneziawg" {
		params = map[string]string{"jc": "3", "jmin": "40", "jmax": "80", "s1": "16", "s2": "24", "s3": "8", "s4": "8", "h1": "1001", "h2": "1002", "h3": "1003", "h4": "1004"}
	}
	var lc net.ListenConfig
	peerConfig := awg.Config{Address: []netip.Addr{netip.MustParseAddr(serverIP)}, PrivateKey: bPriv, PublicKey: aPub, Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), clientPort), AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + mask)}, Parameters: params}
	var listener net.Listener
	var peerEndpoint netip.AddrPort
	if os.Getenv("AMNEZIA_STABILITY_KERNEL_PEER") == "1" {
		peerEndpoint, listener = stabilityKernelPeer(t, peerConfig)
	} else if os.Getenv("AMNEZIA_STABILITY_USERSPACE_TRACE") == "1" {
		peerEndpoint, listener = stabilityUserspaceTracedPeer(t, peerConfig)
	} else {
		peer, err := awg.New(ctx, peerConfig, lc.ListenPacket)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		peerPort, err := peer.LocalPort()
		if err != nil {
			t.Fatal(err)
		}
		peerEndpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), peerPort)
		listener, e = peer.Net.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverIP), 18443))
		if e != nil {
			t.Fatal(e)
		}
		// The listener must outlive the deferred server cleanup, which runs
		// before this peer close.
	}
	counted := &stabilityListener{Listener: listener}
	var wsAccepts, bulkAccepts atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		id := wsAccepts.Add(1)
		for {
			var seq string
			if websocket.Message.Receive(ws, &seq) != nil {
				return
			}
			if websocket.Message.Send(ws, fmt.Sprintf("%d:%s", id, seq)) != nil {
				return
			}
		}
	}))
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, r *http.Request) {
		id := bulkAccepts.Add(1)
		w.Header().Set("X-Connection-ID", fmt.Sprint(id))
		if r.Method == http.MethodPost {
			if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
				http.Error(w, "duplex unavailable", 500)
				return
			}
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			b := make([]byte, 4096)
			for seq := uint64(0); ; seq++ {
				if _, err := io.ReadFull(r.Body, b); err != nil {
					return
				}
				if binary.BigEndian.Uint64(b) != seq {
					return
				}
				for i := 8; i < len(b); i++ {
					if b[i] != byte(seq+uint64(i)) {
						return
					}
				}
				if _, err := w.Write(b[:8]); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		b := make([]byte, 4096)
		for seq := uint64(0); ; seq++ {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
			binary.BigEndian.PutUint64(b, seq)
			for i := 8; i < len(b); i++ {
				b[i] = byte(seq + uint64(i))
			}
			if _, e := w.Write(b); e != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	server := httptest.NewUnstartedServer(mux)
	server.Listener.Close()
	server.Listener = counted
	server.StartTLS()
	// net/http does not own hijacked WebSocket connections. Close their raw
	// sockets too, otherwise a completed test can pin the peer namespace.
	defer func() { counted.closeConnections(); server.CloseClientConnections(); server.Close() }()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	link := &stabilityLink{rng: rand.New(rand.NewSource(604111))}
	host := Underlay{ListenPacket: func(ctx context.Context, n, a string) (net.PacketConn, error) {
		pc, e := lc.ListenPacket(ctx, n, a)
		if e != nil {
			return nil, e
		}
		return &stabilityPacket{PacketConn: pc, link: link}, nil
	}, DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("unexpected DIRECT dial")
	}}
	engineCtx := Context(ctx, host)
	engineCtx = service.ContextWith[adapter.PlatformInterface](engineCtx, loopbackTestPlatform{})
	outbound := map[string]any{"type": protocol, "tag": "vpn", "address": []string{clientIP}, "private_key": aPriv, "public_key": bPub, "endpoint": peerEndpoint.String(), "listen_port": clientPort, "allowed_ips": []string{serverIP + mask}}
	if params != nil {
		outbound["parameters"] = params
	}
	raw, e := json.Marshal(map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"type": "hosts", "tag": "test-dns"}}, "final": "test-dns"}, "outbounds": []any{outbound}, "route": map[string]any{"final": "vpn"}})
	if e != nil {
		t.Fatal(e)
	}
	var runtime *Runtime
	var nativeStop func() error
	var nativeRefresh func() error
	start := func() {
		if os.Getenv("AMNEZIA_STABILITY_HELPER") != "" {
			kind := "awg"
			if protocol == "amnezia-wireguard" {
				kind = "wireguard"
			}
			initialEndpoint := peerEndpoint
			if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
				initialEndpoint = stabilityNativeDomainEndpoint(t, peerEndpoint)
			}
			data := map[string]any{"client_priv_key": aPriv, "server_pub_key": bPub, "client_ip": clientIP, "hostName": initialEndpoint.Addr().String(), "port": initialEndpoint.Port(), "allowed_ips": []string{"0.0.0.0/0", "::/0"}, "mtu": "1280"}
			for k, v := range params {
				data[strings.ToUpper(k[:1])+k[1:]] = v
			}
			profileValues := map[string]any{"protocol": kind, "dns1": "203.0.113.2", "sing_box_routing": map[string]any{"version": 1, "default": "vpn", "rules": []any{}}, kind + "_config_data": data}
			if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
				profileValues["routing_endpoint_host"] = "endpoint.test"
			}
			profile, _ := json.Marshal(profileValues)
			nativeStop, nativeRefresh = stabilityStartNative(t, profile)
			return
		}
		var err error
		runtime, err = StartRuntime(engineCtx, raw, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	closeRuntime := func() error {
		if nativeStop != nil {
			return nativeStop()
		}
		return runtime.Close()
	}
	start()
	defer func() { closeRuntime() }()
	// The application socket is kept for the entire scenario. RouteConnectionEx
	// exercises sing-box's flow ownership, rather than dialing the VPN directly.
	dial := func(context.Context, string, string) (net.Conn, error) {
		if nativeStop != nil {
			c, err := stabilityNativeApplicationDial(ctx, net.JoinHostPort(serverIP, "18443"), os.Getenv("AMNEZIA_STABILITY_EARLY_CAPTURE") == "1")
			if err == nil {
				t.Logf("native application TCP local=%s peer=%s", c.LocalAddr(), c.RemoteAddr())
			}
			return c, err
		}
		app, router := net.Pipe()
		go runtime.box.Router().RouteConnectionEx(ctx, router, adapter.InboundContext{Inbound: TUNTag, Network: "tcp", Source: M.ParseSocksaddr("127.0.0.1:12345"), Destination: M.Socksaddr{Addr: netip.MustParseAddr(serverIP), Port: 18443}}, nil)
		return app, nil
	}
	openWS := func() *websocket.Conn {
		c, e := dial(ctx, "tcp", "")
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(240 * time.Second))
		secure := tls.Client(c, tlsConfig.Clone())
		if e = secure.HandshakeContext(ctx); e != nil {
			c.Close()
			t.Fatal(e)
		}
		config, e := websocket.NewConfig("wss://example.com/ws", "https://example.com")
		if e != nil {
			t.Fatal(e)
		}
		ws, e := websocket.NewClient(config, secure)
		if e != nil {
			secure.Close()
			t.Fatal(e)
		}
		return ws
	}
	ws := openWS()
	defer ws.Close()
	httpTransport := &http.Transport{DialContext: dial, TLSClientConfig: tlsConfig.Clone(), DisableKeepAlives: true}
	defer httpTransport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/bulk", nil)
	recordSize := 4096
	if os.Getenv("AMNEZIA_STABILITY_UPLOAD") == "1" {
		recordSize = 8
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		request, _ = http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/bulk", reader)
		go func() {
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for seq := uint64(0); ; seq++ {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				b := make([]byte, 4096)
				binary.BigEndian.PutUint64(b, seq)
				for i := 8; i < len(b); i++ {
					b[i] = byte(seq + uint64(i))
				}
				if _, err := writer.Write(b); err != nil {
					return
				}
			}
		}()
		t.Log("bulk direction=upload; server validates each record and returns its sequence")
	}
	response, e := (&http.Client{Transport: httpTransport, Timeout: lifetime}).Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.Header.Get("X-Connection-ID") != "1" {
		t.Fatal("unexpected initial bulk connection")
	}
	var messages, chunks atomic.Uint64
	var pauseWS atomic.Bool
	if os.Getenv("AMNEZIA_STABILITY_TRACE") != "" {
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case at := <-ticker.C:
					t.Logf("progress at=%s WS=%d bulk=%d dropped=%d", at.Format(time.RFC3339Nano), messages.Load(), chunks.Load(), link.dropped.Load())
				}
			}
		}()
		defer func() { close(stop); <-done }()
	}
	wsDone, bulkDone := make(chan error, 1), make(chan error, 1)
	go func() {
		for seq := uint64(0); ; seq++ {
			for pauseWS.Load() {
				time.Sleep(20 * time.Millisecond)
			}
			if e := websocket.Message.Send(ws, fmt.Sprint(seq)); e != nil {
				wsDone <- e
				return
			}
			var got string
			if e := websocket.Message.Receive(ws, &got); e != nil {
				wsDone <- e
				return
			}
			if got != fmt.Sprintf("1:%d", seq) {
				wsDone <- fmt.Errorf("WS identity/sequence mismatch: %q", got)
				return
			}
			messages.Add(1)
			time.Sleep(25 * time.Millisecond)
		}
	}()
	go func() {
		b := make([]byte, recordSize)
		for seq := uint64(0); ; seq++ {
			if _, e := io.ReadFull(response.Body, b); e != nil {
				bulkDone <- e
				return
			}
			if binary.BigEndian.Uint64(b) != seq {
				bulkDone <- fmt.Errorf("bulk sequence mismatch")
				return
			}
			for i := 8; i < len(b); i++ {
				if b[i] != byte(seq+uint64(i)) {
					bulkDone <- fmt.Errorf("corrupt bulk payload")
					return
				}
			}
			chunks.Add(1)
		}
	}()
	progressBudget := 100 * time.Second
	waitProgress := func(w, c uint64) {
		t.Helper()
		timer := time.NewTimer(progressBudget)
		defer timer.Stop()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			if messages.Load() >= w && chunks.Load() >= c {
				return
			}
			select {
			case e := <-wsDone:
				t.Fatal("existing WSS closed", e)
			case e := <-bulkDone:
				t.Fatal("existing TLS download closed", e)
			case <-timer.C:
				t.Fatalf("no progress WS=%d/%d bulk=%d/%d", messages.Load(), w, chunks.Load(), c)
			case <-tick.C:
			}
		}
	}
	waitProgress(3, 3)
	if os.Getenv("AMNEZIA_CHAOS_PROFILE") != "" {
		progressBudget = stabilityChaosSeconds("AMNEZIA_CHAOS_RECOVERY_SECONDS", 30)
		stabilityNativeChaos(t, func() { w, c := messages.Load(), chunks.Load(); waitProgress(w+3, c+3) }, pauseWS.Store)
		if counted.accepts.Load() != 2 || wsAccepts.Load() != 1 || bulkAccepts.Load() != 1 {
			t.Fatal("chaos replaced application TCP connections")
		}
	}
	refresh := func() {
		t.Helper()
		var err error
		if nativeRefresh != nil {
			err = nativeRefresh()
		} else {
			err = runtime.RefreshUnderlay(netip.AddrPort{})
		}
		if err != nil {
			t.Fatal("underlay refresh", err)
		}
		if os.Getenv("AMNEZIA_STABILITY_AUTOMATIC") != "1" {
			t.Log("protected UDP refreshed with the same runtime/TUN owner")
		}
	}
	if os.Getenv("AMNEZIA_STABILITY_REFRESH") == "1" && len(pauses) == 0 {
		for range 3 {
			w, c := messages.Load(), chunks.Load()
			refresh()
			waitProgress(w+3, c+3)
			if counted.accepts.Load() != 2 {
				t.Fatal("refresh replaced established connections")
			}
		}
	}
	if os.Getenv("AMNEZIA_STABILITY_DOMAIN_MOVE") == "1" {
		if nativeRefresh == nil {
			t.Fatal("domain move requires native owner")
		}
		w, c := messages.Load(), chunks.Load()
		stabilityNativeDomainMove(t)
		t.Log("old endpoint blackholed; control DNS now points to another address of the same peer")
		refresh()
		progressBudget = 40 * time.Second
		waitProgress(w+3, c+3)
		progressBudget = 100 * time.Second
		if counted.accepts.Load() != 2 {
			t.Fatal("domain migration replaced application connections")
		}
		t.Log("same WSS and bulk TCP survived domain endpoint migration without restarting the runtime")
	}
	if os.Getenv("AMNEZIA_STABILITY_ADDRESS_MOVE") == "1" {
		if nativeRefresh == nil {
			t.Fatal("address move requires the real native owner")
		}
		w, c := messages.Load(), chunks.Load()
		stabilityNativeAddressMove(t)
		refresh()
		progressBudget = 8 * time.Second
		waitProgress(w+3, c+3)
		progressBudget = 100 * time.Second
		if counted.accepts.Load() != 2 {
			t.Fatal("address move replaced application connections")
		}
		t.Log("same WSS and bulk TCP survived removal of the original physical IPv4 address")
	}
	if os.Getenv("AMNEZIA_STABILITY_REMOVE_DEFAULT") == "1" {
		if nativeRefresh == nil {
			t.Fatal("default removal requires native owner")
		}
		w, c := messages.Load(), chunks.Load()
		stabilityNativeRemoveDefault(t)
		if os.Getenv("AMNEZIA_STABILITY_AUTOMATIC") != "1" {
			refresh()
		}
		progressBudget = 8 * time.Second
		waitProgress(w+3, c+3)
		progressBudget = 100 * time.Second
		if counted.accepts.Load() != 2 {
			t.Fatal("default removal replaced established connections")
		}
		t.Log("same WSS and bulk TCP survive with only a native route to the VPN endpoint")
	}
	if os.Getenv("AMNEZIA_STABILITY_INTERFACE_MOVE") == "1" {
		if nativeRefresh == nil {
			t.Fatal("interface move requires native owner")
		}
		w, c := messages.Load(), chunks.Load()
		stabilityNativeInterfaceMove(t)
		refresh()
		progressBudget = 8 * time.Second
		waitProgress(w+3, c+3)
		progressBudget = 100 * time.Second
		if counted.accepts.Load() != 2 {
			t.Fatal("interface migration replaced application connections")
		}
		t.Log("same WSS and bulk TCP survived deletion of the physical interface and switch of gateway/prefix")
	}
	for _, duration := range pauses {
		beforeDrops := link.dropped.Load()
		link.blackhole.Store(true)
		if nativeStop != nil {
			stabilityNativeBlackhole(t, true, peerEndpoint)
		}
		t.Logf("at=%s blackhole start %s: WS=%d bulk=%d accepts=%d", time.Now().Format(time.RFC3339Nano), duration, messages.Load(), chunks.Load(), counted.accepts.Load())
		time.Sleep(duration)
		w, c := messages.Load(), chunks.Load()
		link.blackhole.Store(false)
		if nativeStop != nil {
			link.dropped.Add(stabilityNativeBlackhole(t, false, peerEndpoint))
		}
		recovered := time.Now()
		if os.Getenv("AMNEZIA_STABILITY_REFRESH") == "1" {
			refresh()
		}
		waitProgress(0, c+1)
		firstRecord := time.Since(recovered)
		waitProgress(w+3, c+3)
		t.Logf("first additional complete bulk record after %s; preservation target is three records", firstRecord.Round(time.Millisecond))
		if link.dropped.Load() == beforeDrops {
			t.Fatal("blackhole did not drop encrypted packets")
		}
		if counted.accepts.Load() != 2 || wsAccepts.Load() != 1 || bulkAccepts.Load() != 1 {
			t.Fatal("replacement connection concealed an interruption")
		}
		t.Logf("at=%s same WSS/TLS survived %s; resumed in %s; dropped=%d; accepts=2 WS-ID=1 bulk-ID=1", time.Now().Format(time.RFC3339Nano), duration, time.Since(recovered).Round(time.Millisecond), link.dropped.Load()-beforeDrops)
	}
	if os.Getenv("AMNEZIA_CHAOS_PROFILE") == "" {
		w, c := messages.Load(), chunks.Load()
		beforeDrops := link.dropped.Load()
		link.impaired.Store(true)
		if nativeStop != nil {
			stabilityNativeImpairment(t, true)
		}
		impairStart := time.Now()
		if seconds, err := strconv.Atoi(os.Getenv("AMNEZIA_STABILITY_IMPAIRMENT_SECONDS")); err == nil && seconds > 0 && seconds <= 30 {
			time.Sleep(time.Duration(seconds) * time.Second)
		}
		waitProgress(w+10, c+10)
		t.Logf("impaired progress elapsed=%s WS=%d records=%d verified_bytes=%d", time.Since(impairStart).Round(time.Millisecond), messages.Load()-w, chunks.Load()-c, (chunks.Load()-c)*4096)
		link.impaired.Store(false)
		if nativeStop != nil {
			stabilityNativeImpairment(t, false)
		}
		if nativeStop != nil {
			t.Logf("native netem profile=%s survived; this iproute2 has no seed option", os.Getenv("AMNEZIA_STABILITY_PROFILE"))
		} else {
			t.Logf("10%% loss + 5..20ms delay per direction survived; seed=604111 dropped=%d", link.dropped.Load()-beforeDrops)
		}
		if counted.accepts.Load() != 2 {
			t.Fatal("impairment caused new accept")
		}
	}
	// This is the destructive operation reached by the current reconnect chain.
	closedAt := time.Now()
	if e := closeRuntime(); e != nil {
		t.Fatal(e)
	}
	for name, done := range map[string]<-chan error{"WSS": wsDone, "TLS download": bulkDone} {
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("missing teardown error")
			}
			t.Logf("Runtime.Close destroyed %s after %s: %v", name, time.Since(closedAt).Round(time.Millisecond), e)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not observe teardown", name)
		}
	}
	// Returning availability does not restore the old WS: a new TLS/WS handshake
	// gets a different server ID, with the peer and all configuration unchanged.
	start()
	fresh := openWS()
	defer fresh.Close()
	if e := websocket.Message.Send(fresh, "after-reset"); e != nil {
		t.Fatal(e)
	}
	var got string
	if e := websocket.Message.Receive(fresh, &got); e != nil || got != "2:after-reset" {
		t.Fatalf("new session: %q %v", got, e)
	}
	t.Logf("availability restored with NEW WS-ID=2; accepts=%d; old session irrecoverable", counted.accepts.Load())
}
