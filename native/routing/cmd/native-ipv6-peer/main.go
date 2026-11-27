//go:build (linux && !android) || (darwin && !ios)

// A test-only TCP/UDP origin behind an owned kernel TUN. The sending TCP stack
// is the host kernel; the independent origin uses the project's pinned gVisor.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func bridge(from, to tun.Device) error {
	const offset = 16 // Darwin's TUN needs space for its address-family header.
	bufs := make([][]byte, from.BatchSize())
	sizes := make([]int, len(bufs))
	for i := range bufs {
		bufs[i] = make([]byte, 65535+offset)
	}
	for {
		n, err := from.Read(bufs, sizes, offset)
		if err != nil {
			return err
		}
		packets := make([][]byte, n)
		for i := range packets {
			packets[i] = bufs[i][:offset+sizes[i]]
		}
		if _, err = to.Write(packets, offset); err != nil {
			return err
		}
	}
}

func run() error {
	address := flag.String("address", "", "private IPv6 origin, never assigned to the host")
	tag := flag.String("tag", "", "origin identity A or B")
	flag.Parse()
	remote, err := netip.ParseAddr(*address)
	if err != nil || !remote.Is6() || remote.Is4In6() || !remote.IsPrivate() || (*tag != "A" && *tag != "B") {
		return errors.New("requires a private IPv6 address and tag A/B")
	}
	name := ""
	switch runtime.GOOS {
	case "darwin":
		if os.Getenv("AMNEZIA_NATIVE_IPV6_LAB") != "owned-runner" || os.Getenv("GITHUB_ACTIONS") != "true" {
			return errors.New("Darwin peer requires the explicitly enabled owned CI runner")
		}
		name = "utun"
	case "linux":
		if os.Getenv("AMNEZIA_NATIVE_IPV6_LAB") != "isolated-container" {
			return errors.New("Linux peer requires an isolated container")
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range ifaces {
			if iface.Name != "lo" && !strings.HasPrefix(iface.Name, "amnv6") {
				return fmt.Errorf("unexpected external interface %s", iface.Name)
			}
		}
		name = "amnv6%d"
	default:
		return errors.New("peer supports Darwin/Linux only")
	}
	device, err := tun.CreateTUN(name, 1280)
	if err != nil {
		return err
	}
	defer device.Close()
	name, err = device.Name()
	if err != nil {
		return err
	}
	virtual, stack, err := awg.NewFlowTUN([]netip.Addr{remote}, 1280)
	if err != nil {
		return err
	}
	defer virtual.Close()
	listener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(remote, 18443))
	if err != nil {
		return err
	}
	defer listener.Close()
	udp, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(remote, 18443))
	if err != nil {
		return err
	}
	defer udp.Close()
	var accepted atomic.Uint64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				scanner.Buffer(make([]byte, 256), 4096)
				for scanner.Scan() {
					if _, err := fmt.Fprintf(conn, "%s:%s\n", *tag, scanner.Text()); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(append([]byte(*tag+":"), buf[:n]...), peer); err != nil {
				return
			}
		}
	}()
	go func() {
		for range device.Events() {
		}
	}()
	var pumps sync.WaitGroup
	errorsCh := make(chan error, 2)
	for _, pair := range [][2]tun.Device{{device, virtual}, {virtual, device}} {
		pumps.Add(1)
		go func(from, to tun.Device) { defer pumps.Done(); errorsCh <- bridge(from, to) }(pair[0], pair[1])
	}
	defer func() { device.Close(); virtual.Close(); pumps.Wait() }()
	output := json.NewEncoder(os.Stdout)
	if err := output.Encode(map[string]any{"ready": true, "device": name, "address": remote.String(), "tag": *tag}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case err := <-errorsCh:
			return fmt.Errorf("packet bridge: %w", err)
		default:
		}
		if scanner.Text() == "stop" {
			return nil
		}
		if scanner.Text() != "stats" {
			return errors.New("unknown peer control command")
		}
		if err := output.Encode(map[string]any{"accepted_tcp": accepted.Load()}); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
