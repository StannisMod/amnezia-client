package awg

import (
	"net/netip"
	"testing"
)

func TestFlowMTURespectsInnerAddressFamily(t *testing.T) {
	for _, row := range []struct {
		address string
		mtu     int
		valid   bool
	}{
		{"10.77.0.1", 1200, true}, {"10.77.0.1", 576, true}, {"10.77.0.1", 575, false},
		{"fd77::1", 1200, false}, {"fd77::1", 1280, true}, {"10.77.0.1", 65536, false},
	} {
		if got := validFlowMTU([]netip.Addr{netip.MustParseAddr(row.address)}, row.mtu); got != row.valid {
			t.Errorf("%s mtu %d: %v", row.address, row.mtu, got)
		}
	}
}
