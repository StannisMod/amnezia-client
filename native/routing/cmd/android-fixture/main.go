//go:build !android && !ios

// android-fixture is a disposable emulator peer, never a production server.
// Two observers share one destination IP/port: the host and AWG netstack.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/StannisMod/amnezia-client/native/routing/desktop"
	"github.com/StannisMod/amnezia-client/native/routing/internal/fixturequic"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/miekg/dns"
)

var bulkEnabled bool

var sharedIP = "10.0.2.2" // Android emulator host alias; Windows uses its native local IP.
const tcpPort = 18081
const udpPort = 18082

type fixture struct {
	mu                                   sync.Mutex
	peer                                 *device.Device
	listenPort                           uint16
	closePeer                            []io.Closer
	server, client                       *ecdh.PrivateKey
	directTCP, directUDP, vpnTCP, vpnUDP atomic.Int64
	dnsQueries                           atomic.Int64
	outerRX, outerTX                     atomic.Int64
	quicCertificate                      tls.Certificate
}

// The disposable loopback peer never changes underlay networks. Wrapping the
// stock bind avoids its optional Linux netlink route watcher, so this fixture
// also runs in hosts that permit UDP but forbid netlink sockets.
type fixtureBind struct {
	conn.Bind
	received, sent *atomic.Int64
}

func (b *fixtureBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	functions, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, actualPort, err
	}
	for i, receive := range functions {
		functions[i] = func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
			n, err := receive(packets, sizes, endpoints)
			b.received.Add(int64(n))
			return n, err
		}
	}
	return functions, actualPort, nil
}

func (b *fixtureBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	err := b.Bind.Send(packets, endpoint)
	if err == nil {
		b.sent.Add(int64(len(packets)))
	}
	return err
}

// Optional bounded stream observer used only by the comparative CI benchmark.
func observeBulk(listener net.Listener, label string) {
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(120 * time.Second))
			var size uint32
			if binary.Read(c, binary.BigEndian, &size) != nil || size > 64<<20 {
				return
			}
			if _, err := fmt.Fprintln(c, label); err != nil {
				return
			}
			chunk := bytes.Repeat([]byte{'Z'}, 32<<10)
			left := int(size)
			for left > 0 {
				want := len(chunk)
				if left < want {
					want = left
				}
				n, err := c.Write(chunk[:want])
				if err != nil || n == 0 {
					return
				}
				left -= n
			}
		}()
	}
}

func observeTCP(listener net.Listener, label string, count *atomic.Int64) {
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		count.Add(1)
		go func() { defer c.Close(); fmt.Fprintln(c, label) }()
	}
}

func observeUDP(pc net.PacketConn, label string, count *atomic.Int64) {
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		count.Add(1)
		pc.WriteTo(append([]byte(label+":"), buf[:n]...), from)
	}
}

func (f *fixture) stop() {
	if f.peer != nil {
		f.peer.Close()
		f.peer = nil
	}
	for _, c := range f.closePeer {
		c.Close()
	}
	f.closePeer = nil
}

func (f *fixture) start() error {
	if f.peer != nil {
		return nil
	}
	if len(f.quicCertificate.Certificate) == 0 {
		var err error
		f.quicCertificate, err = fixturequic.Certificate()
		if err != nil {
			return err
		}
	}
	t, stack, err := awg.NewFlowTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("fd77::2"), netip.MustParseAddr(sharedIP)}, 1280)
	if err != nil {
		return err
	}

	cleanup := true
	defer func() {
		if cleanup {
			f.stop()
		}
	}()
	// Omit endpoint on the server: authenticate then learn the emulator's NAT
	// source port. Production outbound endpoint pinning is left unchanged.
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\njc=3\njmin=40\njmax=80\ns1=16\ns2=24\ns3=8\ns4=8\nh1=1001\nh2=1002\nh3=1003\nh4=1004\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.77.0.1/32\nallowed_ip=fd77::1/128\n", hex.EncodeToString(f.server.Bytes()), f.listenPort, hex.EncodeToString(f.client.PublicKey().Bytes()))
	if f.peer, err = awg.NewConfiguredDevice(t, &fixtureBind{Bind: conn.NewDefaultBind(), received: &f.outerRX, sent: &f.outerTX}, ipc); err != nil {
		return err
	}
	ipcStatus, err := f.peer.IpcGet()
	if err != nil {
		return err
	}
	for _, line := range strings.Split(ipcStatus, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return err
			}
			f.listenPort = uint16(port)
		}
	}
	if f.listenPort == 0 {
		return fmt.Errorf("fixture peer did not bind a UDP port")
	}
	for _, ip := range []string{sharedIP, "10.77.0.2", "fd77::2"} {
		if bulkEnabled {
			listener, e := stack.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), 18444))
			if e != nil {
				return e
			}
			f.closePeer = append(f.closePeer, listener)
			go observeBulk(listener, "VPN")
		}
		quicUDP, e := stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), fixturequic.Port))
		if e != nil {
			return e
		}
		f.closePeer = append(f.closePeer, quicUDP)
		quicServer, e := fixturequic.Serve(quicUDP, f.quicCertificate, "VPN")
		if e != nil {
			return e
		}
		f.closePeer = append(f.closePeer, quicServer)
		l, e := stack.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), tcpPort))
		if e != nil {
			return e
		}
		f.closePeer = append(f.closePeer, l)
		go observeTCP(l, "VPN", &f.vpnTCP)
		pc, e := stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), udpPort))
		if e != nil {
			return e
		}
		f.closePeer = append(f.closePeer, pc)
		go observeUDP(pc, "VPN", &f.vpnUDP)
	}
	pc, err := stack.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.2:53"))
	if err != nil {
		return err
	}
	f.closePeer = append(f.closePeer, pc)
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		f.dnsQueries.Add(1)
		a := new(dns.Msg)
		a.SetReply(q)
		for _, question := range q.Question {
			name := strings.ToLower(question.Name)
			if name == "cname.test." {
				a.Answer = append(a.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "vpn.test."})
				name = "vpn.test."
			}
			hdr := dns.RR_Header{Name: name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 30}
			switch question.Qtype {
			case dns.TypeA:
				if name != "ipv6.test." {
					a.Answer = append(a.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(sharedIP)})
				}
			case dns.TypeAAAA:
				a.Answer = append(a.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("fd77::2")})
			}
		}
		w.WriteMsg(a)
	})}
	go server.ActivateAndServe()
	cleanup = false
	return nil
}

func main() {
	flag.BoolVar(&bulkEnabled, "bulk", false, "enable bounded performance-test stream observers")
	flag.StringVar(&sharedIP, "shared-ip", sharedIP, "native host address used by both controlled observers")
	path := flag.String("config", "", "private output fixture JSON (never upload)")
	quicCA := flag.String("quic-ca", "", "public disposable QUIC certificate output")
	probeTCP := flag.String("probe-tcp", "", "native application TCP observer probe")
	probeUDP := flag.String("probe-udp", "", "native application UDP observer probe")
	probeAWG := flag.String("probe-awg", "", "test-only private fixture profile: verify AWG before native capture")
	flag.Parse()
	if *probeAWG != "" {
		if err := probeUnderlayAWG(*probeAWG); err != nil {
			fmt.Fprintln(os.Stderr, "fixture AWG underlay probe failed")
			os.Exit(1)
		}
		fmt.Println("VPN")
		return
	}
	if *probeTCP != "" || *probeUDP != "" {
		network, address := "tcp", *probeTCP
		if *probeUDP != "" {
			network, address = "udp", *probeUDP
		}
		c, err := net.DialTimeout(network, address, 10*time.Second)
		if err != nil {
			panic(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if network == "udp" {
			if _, err = c.Write([]byte("proof")); err != nil {
				panic(err)
			}
		}
		b := make([]byte, 128)
		n, err := c.Read(b)
		if err != nil {
			panic(err)
		}
		fmt.Print(string(b[:n]))
		return
	}
	if *path == "" {
		panic("--config is required")
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	f := &fixture{server: serverKey, client: clientKey}
	if err = f.start(); err != nil {
		panic(err)
	}
	defer f.stop()
	if *quicCA != "" {
		if err = os.WriteFile(*quicCA, f.quicCertificate.Certificate[0], 0644); err != nil {
			panic(err)
		}
	}
	quicUDP, err := net.ListenPacket("udp4", ":18443")
	if err != nil {
		panic(err)
	}
	defer quicUDP.Close()
	quicServer, err := fixturequic.Serve(quicUDP, f.quicCertificate, "DIRECT")
	if err != nil {
		panic(err)
	}
	defer quicServer.Close()
	l, err := net.Listen("tcp4", ":18081")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	u, err := net.ListenPacket("udp4", ":18082")
	if err != nil {
		panic(err)
	}
	defer u.Close()
	go observeTCP(l, "DIRECT", &f.directTCP)
	go observeUDP(u, "DIRECT", &f.directUDP)
	control := http.NewServeMux()
	control.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		// Datagram counts identify delivery/peer response failures without
		// persisting handshake payloads, keys or private UAPI configuration.
		json.NewEncoder(w).Encode(map[string]int64{"direct_tcp": f.directTCP.Load(), "direct_udp": f.directUDP.Load(), "vpn_tcp": f.vpnTCP.Load(), "vpn_udp": f.vpnUDP.Load(), "dns_queries": f.dnsQueries.Load(), "outer_received": f.outerRX.Load(), "outer_sent": f.outerTX.Load()})
	})
	control.HandleFunc("/peer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Query().Get("state") == "off" {
			f.stop()
		} else if err := f.start(); err != nil {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte("OK"))
	})
	admin := &http.Server{Addr: "127.0.0.1:18080", Handler: control}
	// The host alias connects to loopback. CI's disposable runner has no other
	// clients; do not bind the peer control API to a public interface.
	go admin.ListenAndServe()
	defer admin.Close()
	config := map[string]any{
		"protocol": "awg", "description": "Disposable routing fixture", "dns1": "10.77.0.2", "sing_box_dns_path": "vpn",
		"awg_config_data": map[string]any{
			"client_ip": "10.77.0.1/32, fd77::1/128", "client_priv_key": base64.StdEncoding.EncodeToString(clientKey.Bytes()),
			"server_pub_key": base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), "hostName": sharedIP, "port": f.listenPort,
			"allowed_ips": []string{"0.0.0.0/0", "::/0"}, "persistent_keep_alive": "1", "mtu": "1280",
			"Jc": "3", "Jmin": "40", "Jmax": "80", "S1": "16", "S2": "24", "S3": "8", "S4": "8", "H1": "1001", "H2": "1002", "H3": "1003", "H4": "1004",
		},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(*path, raw, 0600); err != nil {
		panic(err)
	}
	fmt.Println("READY: disposable AWG/DNS and independent DIRECT/VPN observers")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	<-stop
}

func probeUnderlayAWG(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var profile map[string]any
	if err = json.Unmarshal(raw, &profile); err != nil {
		return err
	}
	profile["sing_box_routing"] = map[string]any{"version": 1, "default": "vpn", "rules": []any{}}
	raw, err = json.Marshal(profile)
	if err != nil {
		return err
	}
	config, err := desktop.ProfileSession(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var listen net.ListenConfig
	transport, err := awg.New(ctx, config.AWG, func(ctx context.Context, network, address string) (net.PacketConn, error) {
		pc, err := listen.ListenPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &probePacketConn{pc}, nil
	})
	if err != nil {
		return err
	}
	defer transport.Close()
	connection, err := transport.DialContext(ctx, "tcp", "10.77.0.2:18081")
	if err != nil {
		return err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(io.LimitReader(connection, 16))
	if err != nil {
		return err
	}
	if string(data) != "VPN\n" {
		return fmt.Errorf("unexpected fixture observer")
	}
	return nil
}

// Test-only metadata: identify replies rejected by pinned-endpoint validation
// without recording a byte of the encrypted payload or profile.
type probePacketConn struct{ net.PacketConn }

func (c *probePacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, from, err := c.PacketConn.ReadFrom(packet)
	if err == nil {
		fmt.Fprintln(os.Stderr, "fixture AWG datagram source:", from.String())
	}
	return n, from, err
}
