//go:build cgo && amnezia_openvpn_dns

package main

/*
#include "native_dns.h"
*/
import "C"

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/dnsguard"
	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
)

var openvpnDNSHandles sync.Map
var openvpnNextDNSHandle atomic.Int64
var openvpnIPv6Off atomic.Bool
var openvpnDNSPolicy struct {
	sync.Mutex
	generation int64
	next       int64
	preparing  int
	dialing    int
}

func openvpnHasDNSHandles() bool {
	owned := false
	openvpnDNSHandles.Range(func(_, _ any) bool { owned = true; return false })
	return owned
}

//export AmneziaOpenVPNDNSPolicy
func AmneziaOpenVPNDNSPolicy(off C.int32_t) C.int64_t {
	if off != 0 && off != 1 {
		return -1
	}
	openvpnDNSPolicy.Lock()
	defer openvpnDNSPolicy.Unlock()
	if openvpnDNSPolicy.generation != 0 || openvpnDNSPolicy.preparing != 0 || openvpnDNSPolicy.dialing != 0 ||
		openvpnHasDNSHandles() || openvpnDNSPolicy.next == math.MaxInt64 {
		return -1
	}
	openvpnDNSPolicy.next++
	openvpnDNSPolicy.generation = openvpnDNSPolicy.next
	openvpnIPv6Off.Store(off == 1)
	return C.int64_t(openvpnDNSPolicy.generation)
}

//export AmneziaOpenVPNDNSReleasePolicy
func AmneziaOpenVPNDNSReleasePolicy(generation C.int64_t) C.int32_t {
	openvpnDNSPolicy.Lock()
	defer openvpnDNSPolicy.Unlock()
	if generation <= 0 || openvpnDNSPolicy.generation != int64(generation) ||
		openvpnDNSPolicy.preparing != 0 || openvpnDNSPolicy.dialing != 0 || openvpnHasDNSHandles() {
		return 0
	}
	openvpnDNSPolicy.generation = 0
	// No implicit ON transition while native teardown is still being observed.
	return 1
}

//export AmneziaOpenVPNDNSIPv6Off
func AmneziaOpenVPNDNSIPv6Off() C.int32_t {
	if openvpnIPv6Off.Load() {
		return 1
	}
	return 0
}

// Original Cloak calls these BEFORE endpoint processing/socket connect.
// ON is byte-for-byte the old path; OFF has no IPv6 bootstrap exception.
func amneziaCloakEndpointPolicy(host string) error {
	if !openvpnIPv6Off.Load() {
		return nil
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return errors.New("IPv6 OFF Cloak bootstrap requires its original numeric IPv4 endpoint")
	}
	return nil
}

func amneziaCloakSocketPolicy(network, endpoint string) error {
	if !openvpnIPv6Off.Load() {
		return nil
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || !address.Addr().Is4() || (network != "tcp4" && network != "udp4") {
		return errors.New("IPv6 OFF Cloak socket scope unavailable")
	}
	return nil
}

type amneziaCloakDialer struct{ net.Dialer }

func (d *amneziaCloakDialer) Dial(network, endpoint string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, endpoint)
}

func (d *amneziaCloakDialer) DialContext(ctx context.Context, network, endpoint string) (net.Conn, error) {
	openvpnDNSPolicy.Lock()
	openvpnDNSPolicy.dialing++
	off := openvpnIPv6Off.Load()
	openvpnDNSPolicy.Unlock()
	defer func() {
		openvpnDNSPolicy.Lock()
		openvpnDNSPolicy.dialing--
		openvpnDNSPolicy.Unlock()
	}()
	if off {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, errors.New("IPv6 OFF Cloak bootstrap endpoint unavailable")
		}
		if err := amneziaCloakEndpointPolicy(host); err != nil {
			return nil, err
		}
	}
	return d.Dialer.DialContext(ctx, network, endpoint)
}

//export AmneziaOpenVPNDNSProvenance
func AmneziaOpenVPNDNSProvenance() *C.char { return C.CString(openvpnDNSProvenance) }

func nextOpenVPNDNSHandle() int64 {
	for {
		prior := openvpnNextDNSHandle.Load()
		if prior == math.MaxInt64 {
			return -1
		}
		if openvpnNextDNSHandle.CompareAndSwap(prior, prior+1) {
			return prior + 1
		}
	}
}

//export AmneziaOpenVPNDNSStart
func AmneziaOpenVPNDNSStart(address *C.char, policy C.int64_t, host unsafe.Pointer, writer C.AmneziaOVPNPacketWriter,
	dispatch C.AmneziaOVPNDNSDispatch, cancelRequest C.AmneziaOVPNDNSCancel,
	failure C.AmneziaOVPNDNSFailure, release C.AmneziaOVPNHostRelease) C.int64_t {
	if host == nil || release == nil {
		return -1
	}
	// The retained host transfers on entry, including invalid preparation.
	owned := true
	defer func() {
		if owned {
			C.amnezia_ovpn_dns_release(release, host)
		}
	}()
	if address == nil || writer == nil || dispatch == nil || cancelRequest == nil || failure == nil {
		return -1
	}
	openvpnDNSPolicy.Lock()
	if policy <= 0 || openvpnDNSPolicy.generation != int64(policy) || !openvpnIPv6Off.Load() {
		openvpnDNSPolicy.Unlock()
		return -1
	}
	openvpnDNSPolicy.preparing++
	openvpnDNSPolicy.Unlock()
	defer func() {
		openvpnDNSPolicy.Lock()
		openvpnDNSPolicy.preparing--
		openvpnDNSPolicy.Unlock()
	}()
	ip, err := netip.ParseAddr(C.GoString(address))
	if err != nil || !ip.Is4() {
		return -1 // OFF publishes only an IPv4 managed DNS endpoint.
	}
	id := nextOpenVPNDNSHandle()
	if id <= 0 {
		return -1
	}
	// PacketSession now owns release on both successful and failed preparation.
	owned = false
	session, err := dnsguard.NewPacketSession(context.Background(), ip, dnsguard.PacketCallbacks{
		Write: func(packet []byte) bool {
			return C.amnezia_ovpn_dns_write(writer, host, (*C.uint8_t)(unsafe.Pointer(&packet[0])),
				C.int32_t(len(packet))) == 1
		},
		Dispatch: func(request dnsguard.NativeRequest) error {
			network := C.int32_t(0)
			if request.Network == "tcp" {
				network = 1
			}
			timeout := request.Timeout / time.Millisecond
			if timeout < 1 {
				return context.DeadlineExceeded
			}
			if C.amnezia_ovpn_dns_dispatch(dispatch, host, C.int64_t(id), C.uint64_t(request.ID), network,
				(*C.uint8_t)(unsafe.Pointer(&request.Wire[0])), C.int32_t(len(request.Wire)),
				C.int32_t(timeout)) != 1 {
				return errors.New("selected OpenVPN DNS scope rejected dispatch")
			}
			return nil
		},
		Cancel: func(token uint64) {
			C.amnezia_ovpn_dns_cancel(cancelRequest, host, C.int64_t(id), C.uint64_t(token))
		},
		Failed:  func() { C.amnezia_ovpn_dns_failed(failure, host, C.int64_t(id)) },
		Release: func() { C.amnezia_ovpn_dns_release(release, host) },
	})
	if err != nil {
		return -1
	}
	openvpnDNSHandles.Store(id, session)
	return C.int64_t(id)
}

//export AmneziaOpenVPNDNSFeed
func AmneziaOpenVPNDNSFeed(handle C.int64_t, bytes *C.uint8_t, size C.int32_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if !ok || bytes == nil || size <= 0 || size > 65535 {
		return -1
	}
	packet := unsafe.Slice((*byte)(unsafe.Pointer(bytes)), int(size))
	handled := value.(*dnsguard.PacketSession).Feed(packet)
	if handled == 0 && packet[0]>>4 == 6 {
		return 1 // No IPv6 data/control-plane exception under OFF.
	}
	return C.int32_t(handled)
}

//export AmneziaOpenVPNDNSStartScoped
func AmneziaOpenVPNDNSStartScoped(address *C.char, upstream *C.char, policy C.int64_t,
	host unsafe.Pointer, writer C.AmneziaOVPNPacketWriter, bind C.AmneziaOVPNDNSBind,
	failure C.AmneziaOVPNDNSFailure, release C.AmneziaOVPNHostRelease) C.int64_t {
	return startOpenVPNDNSSelected(address, upstream, "plain", "", "", policy, host, writer, bind, failure, release)
}

//export AmneziaOpenVPNDNSStartSelected
func AmneziaOpenVPNDNSStartSelected(address *C.char, upstream *C.char, transport *C.char,
	serverName *C.char, httpsURL *C.char, policy C.int64_t,
	host unsafe.Pointer, writer C.AmneziaOVPNPacketWriter, bind C.AmneziaOVPNDNSBind,
	failure C.AmneziaOVPNDNSFailure, release C.AmneziaOVPNHostRelease) C.int64_t {
	selected := C.GoString(transport)
	if selected == "" {
		selected = "unavailable" // A new metadata call cannot default missing transport to plain.
	}
	return startOpenVPNDNSSelected(address, upstream, selected, C.GoString(serverName), C.GoString(httpsURL),
		policy, host, writer, bind, failure, release)
}

func startOpenVPNDNSSelected(address *C.char, upstream *C.char, transport, serverName, httpsURL string,
	policy C.int64_t, host unsafe.Pointer, writer C.AmneziaOVPNPacketWriter, bind C.AmneziaOVPNDNSBind,
	failure C.AmneziaOVPNDNSFailure, release C.AmneziaOVPNHostRelease) C.int64_t {
	return startOpenVPNDNSSelectedMode(address, upstream, transport, serverName, httpsURL,
		policy, host, writer, bind, failure, release, nil, nil, 0)
}

//export AmneziaOpenVPNDNSStartTunnel
func AmneziaOpenVPNDNSStartTunnel(address *C.char, source *C.char, upstream *C.char,
	transport *C.char, serverName *C.char, httpsURL *C.char, mtu C.int32_t, policy C.int64_t,
	host unsafe.Pointer, writer C.AmneziaOVPNPacketWriter, tunnelWriter C.AmneziaOVPNPacketWriter,
	failure C.AmneziaOVPNDNSFailure, release C.AmneziaOVPNHostRelease) C.int64_t {
	selected := C.GoString(transport)
	if selected == "" {
		selected = "unavailable"
	}
	return startOpenVPNDNSSelectedMode(address, upstream, selected, C.GoString(serverName), C.GoString(httpsURL),
		policy, host, writer, nil, failure, release, source, tunnelWriter, int(mtu))
}

func startOpenVPNDNSSelectedMode(address *C.char, upstream *C.char, transport, serverName, httpsURL string,
	policy C.int64_t, host unsafe.Pointer, writer C.AmneziaOVPNPacketWriter, bind C.AmneziaOVPNDNSBind,
	failure C.AmneziaOVPNDNSFailure, release C.AmneziaOVPNHostRelease,
	source *C.char, tunnelWriter C.AmneziaOVPNPacketWriter, mtu int) C.int64_t {
	if host == nil || release == nil {
		return -1
	}
	owned := true
	defer func() {
		if owned {
			C.amnezia_ovpn_dns_release(release, host)
		}
	}()
	if address == nil || upstream == nil || writer == nil || failure == nil ||
		(source == nil && (bind == nil || tunnelWriter != nil)) ||
		(source != nil && (bind != nil || tunnelWriter == nil)) {
		return -1
	}
	openvpnDNSPolicy.Lock()
	if policy <= 0 || openvpnDNSPolicy.generation != int64(policy) || !openvpnIPv6Off.Load() {
		openvpnDNSPolicy.Unlock()
		return -1
	}
	openvpnDNSPolicy.preparing++
	openvpnDNSPolicy.Unlock()
	defer func() {
		openvpnDNSPolicy.Lock()
		openvpnDNSPolicy.preparing--
		openvpnDNSPolicy.Unlock()
	}()
	ip, err := netip.ParseAddr(C.GoString(address))
	if err != nil || !ip.Is4() {
		return -1
	}
	server, err := netip.ParseAddrPort(C.GoString(upstream))
	if err != nil {
		return -1
	}
	id := nextOpenVPNDNSHandle()
	if id <= 0 {
		return -1
	}
	callbacks := dnsguard.PacketCallbacks{
		Write: func(packet []byte) bool {
			return C.amnezia_ovpn_dns_write(writer, host, (*C.uint8_t)(unsafe.Pointer(&packet[0])),
				C.int32_t(len(packet))) == 1
		},
		Failed:  func() { C.amnezia_ovpn_dns_failed(failure, host, C.int64_t(id)) },
		Release: func() { C.amnezia_ovpn_dns_release(release, host) },
	}
	if source != nil {
		originalSource, err := netip.ParseAddr(C.GoString(source))
		if err != nil {
			return -1
		}
		owned = false
		session, err := dnsguard.NewTunnelPacketSession(context.Background(), ip, originalSource, mtu,
			nativedns.EncryptedServer{Address: server, Transport: transport, ServerName: serverName, HTTPSURL: httpsURL},
			func(packet []byte) bool {
				return C.amnezia_ovpn_dns_write(tunnelWriter, host,
					(*C.uint8_t)(unsafe.Pointer(&packet[0])), C.int32_t(len(packet))) == 1
			}, callbacks)
		if err != nil {
			return -1
		}
		openvpnDNSHandles.Store(id, session)
		return C.int64_t(id)
	}
	exchange, err := nativedns.SelectedResolver(nativedns.EncryptedServer{
		Address: server, Transport: transport, ServerName: serverName, HTTPSURL: httpsURL,
	}, func(ctx context.Context, network string, target netip.AddrPort) (net.Conn, error) {
		if target != server || !target.Addr().Is4() || (network != "tcp4" && network != "udp4") {
			return nil, nativedns.ErrScopeUnavailable
		}
		dialer := &net.Dialer{ControlContext: func(ctx context.Context, actual, endpoint string, raw syscall.RawConn) error {
			if ctx.Err() != nil || actual != network || endpoint != target.String() {
				return nativedns.ErrScopeUnavailable
			}
			bound := false
			err := raw.Control(func(fd uintptr) {
				if fd <= math.MaxInt32 {
					bound = C.amnezia_ovpn_dns_bind(bind, host, C.int64_t(id), C.int32_t(fd)) == 1
				}
			})
			if err != nil || !bound {
				return nativedns.ErrScopeUnavailable
			}
			return ctx.Err()
		}}
		return dialer.DialContext(ctx, network, target.String())
	}, nil)
	if err != nil {
		return -1
	}
	owned = false // Shared session owns host release on both success and failure.
	session, err := dnsguard.NewScopedPacketSession(context.Background(), ip, exchange, callbacks)
	if err != nil {
		return -1
	}
	openvpnDNSHandles.Store(id, session)
	return C.int64_t(id)
}

//export AmneziaOpenVPNDNSFeedTunnel
func AmneziaOpenVPNDNSFeedTunnel(handle C.int64_t, bytes *C.uint8_t, size C.int32_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if !ok || bytes == nil || size < 20 || size > 65535 {
		return 0
	}
	// Borrow only while classifying. PacketSession copies admitted DNS input
	// itself; ordinary native application traffic must not be copied into Go.
	packet := unsafe.Slice((*byte)(unsafe.Pointer(bytes)), int(size))
	return C.int32_t(value.(*dnsguard.PacketSession).FeedTunnel(packet))
}

//export AmneziaOpenVPNDNSComplete
func AmneziaOpenVPNDNSComplete(handle C.int64_t, token C.uint64_t, bytes *C.uint8_t, size C.int32_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if !ok || bytes == nil || size < 12 || size > 65535 {
		return 0
	}
	if value.(*dnsguard.PacketSession).Complete(uint64(token), C.GoBytes(unsafe.Pointer(bytes), C.int(size))) {
		return 1
	}
	return 0
}

//export AmneziaOpenVPNDNSReject
func AmneziaOpenVPNDNSReject(handle C.int64_t, token C.uint64_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if ok && value.(*dnsguard.PacketSession).Reject(uint64(token)) {
		return 1
	}
	return 0
}

//export AmneziaOpenVPNDNSStop
func AmneziaOpenVPNDNSStop(handle C.int64_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if !ok {
		return 0
	}
	session := value.(*dnsguard.PacketSession)
	session.Close()
	// Do not delete before Close: concurrent callers must join the same owner,
	// not interpret absence as permission to release an in-flight native host.
	openvpnDNSHandles.CompareAndDelete(int64(handle), session)
	return 1
}

//export AmneziaOpenVPNDNSQuiesce
func AmneziaOpenVPNDNSQuiesce(handle C.int64_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if !ok {
		return 0
	}
	value.(*dnsguard.PacketSession).Quiesce()
	return 1
}

//export AmneziaOpenVPNDNSResume
func AmneziaOpenVPNDNSResume(handle C.int64_t) C.int32_t {
	value, ok := openvpnDNSHandles.Load(int64(handle))
	if ok && value.(*dnsguard.PacketSession).Resume() {
		return 1
	}
	return 0
}
