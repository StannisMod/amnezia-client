//go:build cgo && amnezia_apple_bridge

package main

/*
#include "amnezia_routing.h"
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/dnsguard"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// A packet-tunnel extension owns one native WG/AWG connection. Shared routing
// does not use this registration or wgTurnOn. Keep the registration across the
// native adapter's temporary backend shutdown/restart on a genuine path outage.
var appleNativeFilter struct {
	sync.RWMutex
	active *applePacketFilter
}
var appleNextPacketFilter atomic.Int64

type applePacketFilter struct {
	id      int64
	host    unsafe.Pointer
	filter  C.AmneziaPacketFilter
	release C.AmneziaHostRelease
}

//export AmneziaNativePacketFilterStart
func AmneziaNativePacketFilterStart(host unsafe.Pointer, filter C.AmneziaPacketFilter, release C.AmneziaHostRelease) C.int64_t {
	if host == nil || release == nil {
		return -1
	}
	appleNativeFilter.Lock()
	if filter == nil || appleNativeFilter.active != nil {
		appleNativeFilter.Unlock()
		C.amnezia_release_host(release, host)
		return -1
	}
	entry := &applePacketFilter{id: appleNextPacketFilter.Add(1), host: host, filter: filter, release: release}
	appleNativeFilter.active = entry
	appleNativeFilter.Unlock()
	return C.int64_t(entry.id)
}

//export AmneziaNativePacketFilterStop
func AmneziaNativePacketFilterStop(handle C.int64_t) {
	appleNativeFilter.Lock()
	entry := appleNativeFilter.active
	if entry == nil || entry.id != int64(handle) {
		appleNativeFilter.Unlock()
		return
	}
	appleNativeFilter.active = nil
	appleNativeFilter.Unlock()
	// The exclusive lock joined every synchronous native packet callback.
	C.amnezia_release_host(entry.release, entry.host)
}

func amneziaNativeFilterPacket(packet []byte) bool {
	if len(packet) == 0 || len(packet) > 65535 {
		return true
	}
	appleNativeFilter.RLock()
	defer appleNativeFilter.RUnlock()
	entry := appleNativeFilter.active
	if entry == nil {
		return false
	}
	return C.amnezia_filter_packet(entry.filter, entry.host, (*C.uint8_t)(unsafe.Pointer(&packet[0])), C.int32_t(len(packet))) != 0
}

//export AmneziaNativePacketFilterFeed
func AmneziaNativePacketFilterFeed(bytes *C.uint8_t, size C.int32_t) C.int32_t {
	if bytes == nil || size <= 0 || size > 65535 {
		return 1
	}
	if amneziaNativeFilterPacket(unsafe.Slice((*byte)(unsafe.Pointer(bytes)), int(size))) {
		return 1
	}
	return 0
}

func amneziaNativeFilterTUN(base tun.Device) tun.Device {
	return dnsguard.WrapPacketFilter(base, amneziaNativeFilterPacket)
}
