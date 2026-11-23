//go:build cgo && amnezia_apple_bridge

package main

/*
#include "amnezia_routing.h"
*/
import "C"

import (
	"sync"
	"syscall"

	"github.com/StannisMod/amnezia-client/native/routing/socketcontrol"
)

var appleXraySockets socketcontrol.Controller
var appleXrayRegister sync.Once
var appleXrayRegisterError error

// Installed by the checked api-xray.go overlay before any exported call.
// Isolated bridge fixtures deliberately have no production dialer registrar.
var amneziaXrayRegisterController func(func(string, string, syscall.RawConn) error) error

//export AmneziaNativeXraySocketsStart
func AmneziaNativeXraySocketsStart(index C.uint32_t, blockIPv6 C.int32_t) C.int64_t {
	if amneziaXrayRegisterController == nil {
		return -1
	}
	appleXrayRegister.Do(func() {
		appleXrayRegisterError = amneziaXrayRegisterController(func(network, address string, conn syscall.RawConn) error {
			return appleXraySockets.Control(conn, func(fd uintptr, index uint32, blocked bool) error {
				block := C.int32_t(0)
				if blocked {
					block = 1
				}
				if C.amnezia_bind_xray_interface(C.int(fd), C.uint32_t(index), block) != 0 {
					return socketcontrol.ErrUnavailable
				}
				return nil
			})
		})
	})
	if appleXrayRegisterError != nil {
		return -1
	}
	return C.int64_t(appleXraySockets.Start(uint32(index), blockIPv6 != 0))
}

//export AmneziaNativeXraySocketsUpdate
func AmneziaNativeXraySocketsUpdate(handle C.int64_t, index C.uint32_t) {
	appleXraySockets.Update(int64(handle), uint32(index))
}

//export AmneziaNativeXraySocketsStop
func AmneziaNativeXraySocketsStop(handle C.int64_t) {
	appleXraySockets.Stop(int64(handle))
}
