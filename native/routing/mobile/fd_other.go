//go:build !linux && !android && !darwin && !ios

package mobile

import "github.com/sagernet/sing-tun"

func closeDescriptor(int) error                    { return unsupported }
func openDescriptor(*tun.Options) (tun.Tun, error) { return nil, unsupported }
