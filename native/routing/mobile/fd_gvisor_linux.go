//go:build linux && with_gvisor

package mobile

import (
	"io"
	"os"
	"sync"

	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

// The pinned gVisor fdbased endpoint leaves its stop eventfd open after each
// detach. Use the existing public packet-flow endpoint with Go's pollable file
// reader instead. This owns exactly one capture FD and one reader; Go's process
// poller is shared across sessions, and no dependency internals are accessed.
type packetDescriptor struct {
	*PacketFlow
	file      *os.File
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	closeErr  error
}

func openDescriptor(opts *tun.Options) (tun.Tun, error) {
	if err := unix.SetNonblock(opts.FileDescriptor, true); err != nil {
		return nil, err
	}
	flow, err := NewPacketFlow(opts.MTU, func(packet []byte) error {
		n, err := unix.Write(opts.FileDescriptor, packet)
		if err == nil && n != len(packet) {
			err = io.ErrShortWrite
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(opts.FileDescriptor), "amnezia-capture")
	if file == nil {
		flow.Close()
		return nil, os.ErrInvalid
	}
	return &packetDescriptor{PacketFlow: flow, file: file, done: make(chan struct{})}, nil
}

func (p *packetDescriptor) Start() error {
	p.startOnce.Do(func() {
		go func() {
			defer close(p.done)
			packet := make([]byte, 65535)
			for {
				n, err := p.file.Read(packet)
				if err != nil {
					return
				}
				if n > 0 {
					if err = p.Feed(packet[:n]); err != nil {
						return
					}
				}
			}
		}()
	})
	return nil
}

func (p *packetDescriptor) Close() error {
	p.closeOnce.Do(func() {
		// Stop synchronous output before closing the descriptor. Nonblocking writes
		// never wait for the packet reader or hold this shutdown path indefinitely.
		p.PacketFlow.Close()
		p.closeErr = p.file.Close()
		p.startOnce.Do(func() { close(p.done) })
		<-p.done
	})
	return p.closeErr
}
