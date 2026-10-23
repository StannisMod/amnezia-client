//go:build linux && !android

package desktop

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"golang.org/x/sys/unix"
)

func DefaultCacheDir() string { return "/var/lib/amneziavpn/domain-routing" }

func PreparePrivateCache(path string) (io.Closer, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("routing cache requires a private absolute path")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func PrepareResolver(config *engine.SessionConfig) error {
	if !config.Resolver.Addr().IsLoopback() {
		return nil
	}
	// Resolve the pre-VPN systemd stub to its numeric native upstream before
	// assigning our link DNS. The OS stub itself remains local and untouched.
	data, err := os.ReadFile("/run/systemd/resolve/resolv.conf")
	if err == nil && config.Resolver.Addr().String() == "127.0.0.53" {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "nameserver" {
				address, err := netip.ParseAddr(parts[1])
				if err == nil && !address.IsLoopback() {
					config.Resolver = netip.AddrPortFrom(address, 53)
					return nil
				}
			}
		}
	}
	return errors.New("cannot bootstrap a local DNS stub; select a numeric upstream DNS server")
}
