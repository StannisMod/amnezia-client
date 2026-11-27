//go:build cgo && amnezia_native_dns

// Overlaid into the existing amnezia-xray-bindings package main, so all native
// desktop adapters use the service's already-linked Go runtime.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"sync"

	"github.com/StannisMod/amnezia-client/native/routing/nativedns"
)

var nativeDNS = struct {
	sync.Mutex
	next     int64
	sessions map[int64]*nativedns.Session
}{sessions: make(map[int64]*nativedns.Session)}

//export amnezia_native_dns_start
func amnezia_native_dns_start(raw *C.char) C.int64_t {
	if raw == nil {
		return -1
	}
	config, err := nativedns.ParseConfig(C.GoString(raw))
	if err != nil {
		return -1
	}
	nativeDNS.Lock()
	defer nativeDNS.Unlock()
	// A prepared replacement must coexist with its still-published predecessor.
	// Conflicting endpoints are rejected by the actual listener bind, not by
	// prematurely closing the old resolver generation.
	if len(nativeDNS.sessions) >= 16 || nativeDNS.next == int64(^uint64(0)>>1) {
		return -1
	}
	session, err := nativedns.Start(context.Background(), config)
	if err != nil {
		return -1
	}
	nativeDNS.next++
	nativeDNS.sessions[nativeDNS.next] = session
	return C.int64_t(nativeDNS.next)
}

//export amnezia_native_dns_alive
func amnezia_native_dns_alive(handle C.int64_t) C.int32_t {
	nativeDNS.Lock()
	defer nativeDNS.Unlock()
	session := nativeDNS.sessions[int64(handle)]
	if session == nil {
		return 0
	}
	select {
	case <-session.Done():
		return 0
	default:
		return 1
	}
}

//export amnezia_native_dns_quiesce
func amnezia_native_dns_quiesce(handle C.int64_t) C.int32_t {
	nativeDNS.Lock()
	defer nativeDNS.Unlock()
	session := nativeDNS.sessions[int64(handle)]
	if session == nil {
		return 0
	}
	session.Quiesce()
	return 1
}

//export amnezia_native_dns_stop
func amnezia_native_dns_stop(handle C.int64_t) C.int32_t {
	nativeDNS.Lock()
	defer nativeDNS.Unlock()
	session := nativeDNS.sessions[int64(handle)]
	if session == nil {
		return 0
	}
	_ = session.Close()
	delete(nativeDNS.sessions, int64(handle))
	return 1
}
