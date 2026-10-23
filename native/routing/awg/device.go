package awg

import (
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// NewConfiguredDevice takes ownership of the TUN and applies UAPI before any
// packet is consumed. The pinned AWG reader snapshots S4 before calling Read;
// its first iteration must therefore finish empty after configuration, so the
// next iteration reloads the configured offset. Merely blocking that first
// Read would still encrypt the first packet with the old padding layout.
func NewConfiguredDevice(t tun.Device, bind conn.Bind, ipc string) (*device.Device, error) {
	gated := &configuredTUN{Device: t, ready: make(chan struct{}), events: make(chan tun.Event)}
	d := device.NewDevice(gated, bind, device.NewLogger(device.LogLevelSilent, ""))
	err := d.IpcSet(ipc)
	gated.release()
	if err == nil {
		err = d.Up()
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

type configuredTUN struct {
	tun.Device
	ready       chan struct{}
	events      chan tun.Event
	first       atomic.Bool
	releaseOnce sync.Once
	closeOnce   sync.Once
	closeErr    error
}

func (t *configuredTUN) release() { t.releaseOnce.Do(func() { close(t.ready) }) }
func (t *configuredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if t.first.CompareAndSwap(false, true) {
		<-t.ready
		return 0, nil
	}
	return t.Device.Read(bufs, sizes, offset)
}

// Startup is explicit in NewConfiguredDevice. Do not forward the netstack's
// eager EventUp while UAPI is still being applied.
func (t *configuredTUN) Events() <-chan tun.Event { return t.events }
func (t *configuredTUN) Close() error {
	t.closeOnce.Do(func() { t.release(); t.closeErr = t.Device.Close(); close(t.events) })
	return t.closeErr
}
