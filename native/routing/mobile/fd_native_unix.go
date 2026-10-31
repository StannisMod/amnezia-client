//go:build darwin || ios || (linux && !with_gvisor)

package mobile

import (
	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

func openDescriptor(opts *tun.Options) (tun.Tun, error) {
	if err := unix.SetNonblock(opts.FileDescriptor, true); err != nil {
		return nil, err
	}
	return tun.New(*opts)
}
