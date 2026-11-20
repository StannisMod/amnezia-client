package dnsguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// NativeTUN interposes only a reserved managed-DNS address. It does not proxy
// native application traffic, create an OS interface or install routes.
type NativeTUN struct {
	tun.Device
	frontend *Frontend
	address  netip.Addr
	done     chan struct{}
	once     sync.Once
	closeErr error
}

// WrapNativeTUN takes ownership of base only on success. The native adapter
// must publish the same address as managed DNS only after this succeeds.
// Exchange must be routed by the native host through its original DNS scope,
// not back to the managed-DNS address.
func WrapNativeTUN(ctx context.Context, base tun.Device, address netip.Addr, exchange Exchange) (*NativeTUN, error) {
	if base == nil {
		return nil, errors.New("native DNS guard requires an owned TUN")
	}
	frontend, err := New(ctx, address, exchange)
	if err != nil {
		return nil, err
	}
	n := &NativeTUN{Device: base, frontend: frontend, address: address, done: make(chan struct{})}
	go n.writeReplies()
	go func() { <-frontend.Done(); _ = n.Close() }()
	return n, nil
}

func (n *NativeTUN) writeReplies() {
	defer close(n.done)
	data, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
	for {
		count, err := n.frontend.Device().Read(data, sizes, 0)
		if err != nil {
			return
		}
		if count > 0 {
			if _, err := n.Device.Write([][]byte{data[0][:sizes[0]]}, 0); err != nil {
				// Do not leave a published but orphaned DNS service. Close is
				// performed by the Done observer, not this output goroutine.
				n.frontend.cancel()
				return
			}
		}
	}
}

func dnsDestination(packet []byte, address netip.Addr) bool {
	if len(packet) >= 20 && packet[0]>>4 == 4 && address.Is4() {
		return netip.AddrFrom4([4]byte(packet[16:20])) == address
	}
	if len(packet) >= 40 && packet[0]>>4 == 6 && address.Is6() {
		return netip.AddrFrom16([16]byte(packet[24:40])) == address
	}
	return false
}

func (n *NativeTUN) Read(data [][]byte, sizes []int, offset int) (int, error) {
	for {
		count, readErr := n.Device.Read(data, sizes, offset)
		kept := 0
		for i := 0; i < count; i++ {
			packet := data[i][offset : offset+sizes[i]]
			if dnsDestination(packet, n.address) {
				if _, err := n.frontend.Device().Write([][]byte{packet}, 0); err != nil {
					return kept, err
				}
			} else {
				if kept != i {
					copy(data[kept][offset:], packet)
				}
				sizes[kept] = sizes[i]
				kept++
			}
		}
		if kept > 0 || readErr != nil {
			return kept, readErr
		}
	}
}

func (n *NativeTUN) Close() error {
	n.once.Do(func() {
		frontErr := n.frontend.Close()
		baseErr := n.Device.Close()
		<-n.done
		n.closeErr = errors.Join(frontErr, baseErr)
	})
	return n.closeErr
}
