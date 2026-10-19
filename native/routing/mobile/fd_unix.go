//go:build linux || android || darwin || ios

package mobile

import (
	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

func closeDescriptor(fd int) error { return unix.Close(fd) }
func openDescriptor(opts *tun.Options) (tun.Tun, error) {
	if err := unix.SetNonblock(opts.FileDescriptor, true); err != nil {
		return nil, err
	}
	return tun.New(*opts)
}
