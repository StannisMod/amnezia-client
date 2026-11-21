//go:build cgo && amnezia_apple_bridge

package main

/*
#include "amnezia_routing.h"
*/
import "C"

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/StannisMod/amnezia-client/native/routing/dnsguard"
)

type appleNativeDNS struct {
	mu       sync.RWMutex
	closed   bool
	failed   atomic.Bool
	id       int64
	host     unsafe.Pointer
	writer   C.AmneziaPacketWriter
	failure  C.AmneziaDNSFailure
	release  C.AmneziaHostRelease
	cancel   context.CancelFunc
	frontend *dnsguard.Frontend
	exchange *dnsguard.NativeExchange
	done     chan struct{}
}

var appleNativeDNSHandles sync.Map
var appleNextNativeDNSHandle atomic.Int64

//export AmneziaNativeDNSStart
func AmneziaNativeDNSStart(address *C.char, host unsafe.Pointer, writer C.AmneziaPacketWriter, dispatch C.AmneziaDNSDispatch, cancelRequest C.AmneziaDNSCancel, failure C.AmneziaDNSFailure, release C.AmneziaHostRelease) C.int64_t {
	if host == nil || release == nil {
		return -1
	}
	owned := true
	defer func() {
		if owned {
			C.amnezia_release_host(release, host)
		}
	}()
	if address == nil || writer == nil || dispatch == nil || cancelRequest == nil || failure == nil {
		return -1
	}
	ip, err := netip.ParseAddr(C.GoString(address))
	if err != nil {
		return -1
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &appleNativeDNS{id: appleNextNativeDNSHandle.Add(1), host: host, writer: writer,
		failure: failure, release: release, cancel: cancel, done: make(chan struct{})}
	s.exchange, err = dnsguard.NewNativeExchange(func(request dnsguard.NativeRequest) error {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.closed || ctx.Err() != nil {
			return context.Canceled
		}
		network := C.int32_t(0)
		if request.Network == "tcp" {
			network = 1
		}
		timeout := request.Timeout / time.Millisecond
		if timeout < 1 {
			return context.DeadlineExceeded
		}
		if C.amnezia_dns_dispatch(dispatch, host, C.int64_t(s.id), C.uint64_t(request.ID), network,
			(*C.uint8_t)(unsafe.Pointer(&request.Wire[0])), C.int32_t(len(request.Wire)), C.int32_t(timeout)) != 1 {
			return errors.New("native DNS scope rejected dispatch")
		}
		return nil
	}, func(id uint64) {
		// Retained host remains owned until exchange.Close has joined every
		// dispatch/cancel call, including cancellation during Stop.
		C.amnezia_dns_cancel(cancelRequest, host, C.int64_t(s.id), C.uint64_t(id))
	})
	if err != nil {
		cancel()
		return -1
	}
	s.frontend, err = dnsguard.New(ctx, ip, s.exchange.Exchange)
	if err != nil {
		cancel()
		s.exchange.Close()
		return -1
	}
	appleNativeDNSHandles.Store(s.id, s)
	owned = false
	go s.writeReplies()
	return C.int64_t(s.id)
}

func (s *appleNativeDNS) reportFailure() {
	if !s.failed.CompareAndSwap(false, true) {
		return
	}
	s.cancel()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.closed {
		C.amnezia_dns_failure(s.failure, s.host, C.int64_t(s.id))
	}
}

func (s *appleNativeDNS) writeReplies() {
	defer close(s.done)
	data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
	for {
		count, err := s.frontend.Device().Read(data, sizes, 0)
		if err != nil {
			s.reportFailure()
			return
		}
		if count > 0 {
			s.mu.RLock()
			if s.closed {
				s.mu.RUnlock()
				return
			}
			ok := C.amnezia_write_packet(s.writer, s.host, (*C.uint8_t)(unsafe.Pointer(&data[0][0])), C.int32_t(sizes[0]))
			s.mu.RUnlock()
			if ok != 1 {
				s.reportFailure()
				return
			}
		}
	}
}

//export AmneziaNativeDNSFeed
func AmneziaNativeDNSFeed(handle C.int64_t, bytes *C.uint8_t, size C.int32_t) C.int32_t {
	value, ok := appleNativeDNSHandles.Load(int64(handle))
	if !ok || bytes == nil || size <= 0 || size > 65535 {
		return -1
	}
	s := value.(*appleNativeDNS)
	// Classify borrowed bytes without copying native application traffic.
	// Only DNS-owned packets cross into the asynchronous frontend.
	packet := unsafe.Slice((*byte)(unsafe.Pointer(bytes)), int(size))
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return -1
	}
	if !s.frontend.HandlesPacket(packet) {
		s.mu.RUnlock()
		return 0
	}
	ownedPacket := C.GoBytes(unsafe.Pointer(bytes), C.int(size))
	_, err := s.frontend.Device().Write([][]byte{ownedPacket}, 0)
	s.mu.RUnlock()
	if err != nil {
		s.reportFailure()
		return -1
	}
	return 1
}

//export AmneziaNativeDNSComplete
func AmneziaNativeDNSComplete(handle C.int64_t, token C.uint64_t, bytes *C.uint8_t, size C.int32_t) C.int32_t {
	value, ok := appleNativeDNSHandles.Load(int64(handle))
	if !ok || bytes == nil || size < 12 || size > 65535 {
		return 0
	}
	if value.(*appleNativeDNS).exchange.Complete(uint64(token), C.GoBytes(unsafe.Pointer(bytes), C.int(size))) {
		return 1
	}
	return 0
}

//export AmneziaNativeDNSReject
func AmneziaNativeDNSReject(handle C.int64_t, token C.uint64_t) C.int32_t {
	value, ok := appleNativeDNSHandles.Load(int64(handle))
	if ok && value.(*appleNativeDNS).exchange.Reject(uint64(token)) {
		return 1
	}
	return 0
}

//export AmneziaNativeDNSStop
func AmneziaNativeDNSStop(handle C.int64_t) {
	value, ok := appleNativeDNSHandles.LoadAndDelete(int64(handle))
	if !ok {
		return
	}
	s := value.(*appleNativeDNS)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.frontend.Close()
	s.exchange.Close()
	<-s.done
	C.amnezia_release_host(s.release, s.host)
}
