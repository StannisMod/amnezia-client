//go:build linux && with_gvisor

package mobile

import (
	"io"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

// A stable packet-flow endpoint owns the stack independently of the capture
// descriptor. Operations serialize handover/start/close; fileMu prevents an
// output write from racing descriptor retirement. A replacement reader starts
// only after the old reader has returned.
type packetDescriptor struct {
	*PacketFlow
	operations sync.Mutex
	fileMu     sync.RWMutex
	file       *os.File
	fd         int
	done       chan struct{}
	started    bool
	closed     bool
	closeErr   error
}

func openDescriptor(opts *tun.Options) (tun.Tun, error) {
	if err := unix.SetNonblock(opts.FileDescriptor, true); err != nil {
		return nil, err
	}
	p := &packetDescriptor{done: make(chan struct{}), fd: opts.FileDescriptor}
	flow, err := NewPacketFlow(opts.MTU, p.writeCapture)
	if err != nil {
		return nil, err
	}
	p.PacketFlow = flow
	p.file = os.NewFile(uintptr(opts.FileDescriptor), "amnezia-capture")
	if p.file == nil {
		flow.Close()
		return nil, os.ErrInvalid
	}
	return p, nil
}

func (p *packetDescriptor) writeCapture(packet []byte) error {
	p.fileMu.RLock()
	defer p.fileMu.RUnlock()
	n, err := unix.Write(p.fd, packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	return err
}

func (p *packetDescriptor) startReader() {
	file, done := p.file, p.done
	go func() {
		defer close(done)
		packet := make([]byte, 65535)
		for {
			n, err := file.Read(packet)
			if err != nil || n == 0 {
				return
			}
			if err = p.Feed(packet[:n]); err != nil {
				return
			}
		}
	}()
}

func (p *packetDescriptor) Start() error {
	p.operations.Lock()
	defer p.operations.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	if !p.started {
		p.started = true
		p.startReader()
	}
	return nil
}

// replaceDescriptor consumes a freshly owned descriptor on every path. It is
// deliberately internal until Android's UID-range handover is proven. The
// PacketFlow endpoint, gVisor stack and established connections never restart.
func (p *packetDescriptor) replaceDescriptor(fd int) error {
	// os.NewFile must observe O_NONBLOCK when it registers the descriptor
	// with Go's poller; setting it afterwards makes an idle read return EAGAIN.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), "amnezia-capture-replacement")
	if file == nil {
		return os.ErrInvalid
	}
	accepted := false
	defer func() {
		if !accepted {
			file.Close()
		}
	}()
	p.operations.Lock()
	defer p.operations.Unlock()
	if p.closed || !p.started {
		return net.ErrClosed
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	p.fileMu.Lock()
	old := p.file
	p.file = file
	p.fd = fd
	p.fileMu.Unlock()
	// Closing a Go pollable file interrupts its pending read. No second reader
	// can consume application packets until that read loop has fully retired.
	old.Close()
	<-p.done
	p.done = make(chan struct{})
	p.startReader()
	accepted = true
	return nil
}

func (p *packetDescriptor) CaptureError() error {
	p.operations.Lock()
	defer p.operations.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
		return nil
	}
}

func (p *packetDescriptor) Close() error {
	p.operations.Lock()
	defer p.operations.Unlock()
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	p.PacketFlow.Close()
	p.fileMu.Lock()
	p.closeErr = p.file.Close()
	p.fileMu.Unlock()
	if !p.started {
		close(p.done)
	}
	<-p.done
	return p.closeErr
}
