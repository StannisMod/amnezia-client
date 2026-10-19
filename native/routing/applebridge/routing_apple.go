//go:build cgo && amnezia_apple_bridge

// Overlaid into AWG/XRay's existing package main: one c-archive/Go runtime.
package main

/*
#include "amnezia_routing.h"
*/
import "C"

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/mobile"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

type appleRoutingSession struct {
	sync.RWMutex
	session *mobile.Session
	flow    *mobile.PacketFlow
	closed  bool
}

var appleRoutingHandles sync.Map
var appleNextRoutingHandle atomic.Int64

//export AmneziaRoutingStart
func AmneziaRoutingStart(raw *C.char, size C.int32_t, host unsafe.Pointer, writer C.AmneziaPacketWriter, release C.AmneziaHostRelease) C.int64_t {
	if host == nil || writer == nil || release == nil {
		return -1
	}
	owned := true
	defer func() {
		if owned {
			C.amnezia_release_host(release, host)
		}
	}()
	if raw == nil || size <= 0 || size > 4<<20 {
		return -1
	}
	flow, err := mobile.NewPacketFlow(1280, func(packet []byte) error {
		if len(packet) == 0 {
			return nil
		}
		if C.amnezia_write_packet(writer, host, (*C.uint8_t)(unsafe.Pointer(&packet[0])), C.int32_t(len(packet))) != 1 {
			return errors.New("native packet delivery failed")
		}
		return nil
	})
	if err != nil {
		return -1
	}
	platform, err := mobile.New(-1, mobile.Hooks{
		// NEPacketTunnelProvider-created sockets use the underlying network with
		// includeAllNetworks=false. The containing app never opens these sockets.
		Protect: func(int) error { return nil },
		Interfaces: func() ([]adapter.NetworkInterface, error) {
			interfaces, err := net.Interfaces()
			if err != nil {
				return nil, err
			}
			result := make([]adapter.NetworkInterface, 0, len(interfaces))
			for _, i := range interfaces {
				converted, err := control.InterfaceFromNet(i)
				if err != nil {
					return nil, err
				}
				result = append(result, adapter.NetworkInterface{Interface: converted})
			}
			return result, nil
		},
		Open:             func(*tun.Options) (tun.Tun, error) { return flow, nil },
		Release:          func() { flow.Close(); C.amnezia_release_host(release, host) },
		NetworkExtension: true,
	})
	if err != nil {
		flow.Close()
		return -1
	}
	owned = false // Platform owns the retained native host from this point.
	session, err := mobile.Start(context.Background(), platform, C.GoBytes(unsafe.Pointer(raw), C.int(size)))
	if err != nil {
		return -1
	}
	handle := appleNextRoutingHandle.Add(1)
	appleRoutingHandles.Store(handle, &appleRoutingSession{session: session, flow: flow})
	return C.int64_t(handle)
}

//export AmneziaRoutingStop
func AmneziaRoutingStop(handle C.int64_t) {
	value, ok := appleRoutingHandles.LoadAndDelete(int64(handle))
	if !ok {
		return
	}
	s := value.(*appleRoutingSession)
	s.Lock()
	defer s.Unlock()
	s.closed = true
	s.session.Close()
}

//export AmneziaRoutingFeed
func AmneziaRoutingFeed(handle C.int64_t, data *C.uint8_t, size C.int32_t) C.int32_t {
	if data == nil || size <= 0 || size > 65535 {
		return -1
	}
	value, ok := appleRoutingHandles.Load(int64(handle))
	if !ok {
		return -1
	}
	s := value.(*appleRoutingSession)
	s.RLock()
	defer s.RUnlock()
	if s.closed || s.flow.Feed(unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size))) != nil {
		return -1
	}
	return 0
}

//export AmneziaRoutingStats
func AmneziaRoutingStats(handle C.int64_t, rx, tx, handshake *C.uint64_t) C.int32_t {
	if rx == nil || tx == nil || handshake == nil {
		return -1
	}
	value, ok := appleRoutingHandles.Load(int64(handle))
	if !ok {
		return -1
	}
	s := value.(*appleRoutingSession)
	s.RLock()
	defer s.RUnlock()
	if s.closed {
		return -1
	}
	stats, err := s.session.Stats()
	if err != nil {
		return -1
	}
	*rx, *tx, *handshake = C.uint64_t(stats.RXBytes), C.uint64_t(stats.TXBytes), C.uint64_t(stats.LastHandshake)
	return 0
}
