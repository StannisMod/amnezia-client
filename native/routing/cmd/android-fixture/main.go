//go:build !android && !ios

// android-fixture is a disposable emulator peer, never a production server.
// Two observers share one destination IP/port: the host and AWG netstack.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/miekg/dns"
)

const sharedIP = "10.0.2.2" // Android emulator's documented host alias.
const tcpPort = 18081
const udpPort = 18082

type fixture struct {
	mu                                   sync.Mutex
	peer                                 *device.Device
	closePeer                            []io.Closer
	server, client                       *ecdh.PrivateKey
	directTCP, directUDP, vpnTCP, vpnUDP atomic.Int64
}

// The disposable loopback peer never changes underlay networks. Wrapping the
// stock bind avoids its optional Linux netlink route watcher, so this fixture
// also runs in hosts that permit UDP but forbid netlink sockets.
type fixtureBind struct{ conn.Bind }

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
	t, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("fd77::2"), netip.MustParseAddr(sharedIP)}, nil, 1280)
	if err != nil {
		return err
	}
	f.peer = device.NewDevice(t, &fixtureBind{conn.NewDefaultBind()}, device.NewLogger(device.LogLevelSilent, ""))
	cleanup := true
	defer func() {
		if cleanup {
			f.stop()
		}
	}()
	// Omit endpoint on the server: authenticate then learn the emulator's NAT
	// source port. Production outbound endpoint pinning is left unchanged.
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=51820\njc=3\njmin=40\njmax=80\ns1=16\ns2=24\ns3=8\ns4=8\nh1=1001\nh2=1002\nh3=1003\nh4=1004\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=10.77.0.1/32\nallowed_ip=fd77::1/128\n", hex.EncodeToString(f.server.Bytes()), hex.EncodeToString(f.client.PublicKey().Bytes()))
	if err = f.peer.IpcSet(ipc); err != nil {
		return err
	}
	if err = f.peer.Up(); err != nil {
		return err
	}
	for _, ip := range []string{sharedIP, "fd77::2"} {
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
	path := flag.String("config", "", "private output fixture JSON (never upload)")
	flag.Parse()
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
		json.NewEncoder(w).Encode(map[string]int64{"direct_tcp": f.directTCP.Load(), "direct_udp": f.directUDP.Load(), "vpn_tcp": f.vpnTCP.Load(), "vpn_udp": f.vpnUDP.Load()})
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
			"server_pub_key": base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), "hostName": sharedIP, "port": 51820,
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
