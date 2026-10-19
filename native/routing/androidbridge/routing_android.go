//go:build android && cgo && amnezia_android_bridge

// This file is overlaid into the existing AWG Android package main. Do not
// build a second Go .so: old AWG JNI and routed JNI share libwg-go's runtime.
package main

/*
#include <stdlib.h>
#include "routing_host.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/mobile"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

var routedSessions = struct {
	sync.Mutex
	sessions map[int64]*mobile.Session
}{sessions: make(map[int64]*mobile.Session)}
var nextRoutedHandle atomic.Int64

//export RoutingStart
func RoutingStart(fd int32, raw string, host C.uintptr_t) int64 {
	hooks := mobile.Hooks{
		Protect: func(fd int) error {
			if C.amnezia_routing_protect(host, C.int(fd)) != 1 {
				return errors.New("native socket protection failed")
			}
			return nil
		},
		Interfaces: func() ([]adapter.NetworkInterface, error) {
			data := C.amnezia_routing_interfaces(host)
			if data == nil {
				return nil, errors.New("native network inventory unavailable")
			}
			defer C.free(unsafe.Pointer(data))
			var rows []struct {
				Index     int            `json:"index"`
				Name      string         `json:"name"`
				MTU       int            `json:"mtu"`
				Flags     uint           `json:"flags"`
				Addresses []netip.Prefix `json:"addresses"`
			}
			if err := json.Unmarshal([]byte(C.GoString(data)), &rows); err != nil {
				return nil, errors.New("invalid native network inventory")
			}
			interfaces := make([]adapter.NetworkInterface, 0, len(rows))
			for _, r := range rows {
				interfaces = append(interfaces, adapter.NetworkInterface{Interface: control.Interface{Index: r.Index, Name: r.Name, MTU: r.MTU, Flags: net.Flags(r.Flags), Addresses: r.Addresses}})
			}
			return interfaces, nil
		},
		Release: func() { C.amnezia_routing_release(host) },
	}
	platform, err := mobile.New(int(fd), hooks)
	if err != nil {
		if fd >= 0 {
			unix.Close(int(fd))
		}
		hooks.Release()
		return -1
	}
	session, err := mobile.Start(context.Background(), platform, []byte(raw))
	if err != nil {
		return -1
	}
	handle := nextRoutedHandle.Add(1)
	routedSessions.Lock()
	routedSessions.sessions[handle] = session
	routedSessions.Unlock()
	return handle
}

//export RoutingStop
func RoutingStop(handle int64) {
	routedSessions.Lock()
	session := routedSessions.sessions[handle]
	delete(routedSessions.sessions, handle)
	routedSessions.Unlock()
	if session != nil {
		session.Close()
	}
}

//export RoutingReadStats
func RoutingReadStats(handle int64, rx, tx, handshake *C.longlong) C.int {
	routedSessions.Lock()
	session := routedSessions.sessions[handle]
	routedSessions.Unlock()
	if session == nil {
		return -1
	}
	stats, err := session.Stats()
	if err != nil {
		return -1
	}
	*rx = C.longlong(stats.RXBytes)
	*tx = C.longlong(stats.TXBytes)
	*handshake = C.longlong(stats.LastHandshake)
	return 0
}
