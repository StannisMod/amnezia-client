//go:build windows

package desktop

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/StannisMod/amnezia-client/native/routing/engine"
	"golang.org/x/sys/windows"
)

func DefaultCacheDir() string {
	// The helper runs as the service identity. LocalSystem's profile is private;
	// do not create a privileged writable directory in shared user storage.
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "AmneziaVPN", "domain-routing")
}

func PreparePrivateCache(path string) (io.Closer, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("routing cache requires a private absolute path")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func PrepareResolver(config *engine.SessionConfig) error {
	if config.Resolver.Addr().IsLoopback() {
		return errors.New("a native numeric upstream resolver is required on Windows")
	}
	return nil
}
