package dnsguard

import "github.com/amnezia-vpn/amneziawg-go/v3/tun"

// FilterTUN keeps the native backend's sole OS reader. A synchronous filter may
// consume DNS packets or reject IPv6; everything else retains its original
// bytes, batch order and headroom. The callback must not retain borrowed data.
type FilterTUN struct {
	tun.Device
	filter func([]byte) bool
}

func WrapPacketFilter(base tun.Device, filter func([]byte) bool) tun.Device {
	return &FilterTUN{Device: base, filter: filter}
}

func (t *FilterTUN) Read(data [][]byte, sizes []int, offset int) (int, error) {
	for {
		count, err := t.Device.Read(data, sizes, offset)
		kept := 0
		for i := 0; i < count; i++ {
			packet := data[i][offset : offset+sizes[i]]
			if t.filter != nil && t.filter(packet) {
				continue
			}
			if kept != i {
				copy(data[kept][offset:], packet)
			}
			sizes[kept] = sizes[i]
			kept++
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}
