//go:build linux && !android

package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func markerProbe(t *testing.T, family int, mark int) int {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if mark != 0 {
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
			t.Fatal(err)
		}
	}
	if family == unix.AF_INET {
		unix.Connect(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	} else {
		unix.Connect(fd, &unix.SockaddrInet6{Addr: [16]byte{15: 1}})
	}
	value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestStableTCPSourceMarkerIsolationAndLifetime(t *testing.T) {
	if os.Getenv("AMNEZIA_SOURCE_MARKER_TEST") != "1" {
		t.Skip("requires the private privileged cgroup/netns fixture")
	}
	group, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || strings.TrimSpace(string(group)) != "0::/" {
		t.Fatal("refusing marker test outside private cgroup namespace")
	}
	procs, err := os.ReadFile("/sys/fs/cgroup/cgroup.procs")
	if err != nil {
		t.Fatal(err)
	}
	own := false
	for _, p := range strings.Fields(string(procs)) {
		if p == strconv.Itoa(os.Getpid()) {
			own = true
		}
	}
	if !own {
		t.Fatal("refusing to attach outside this container's own cgroup")
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if markerProbe(t, family, 0)&int(captureMark) != 0 {
			t.Fatal("fixture already marked")
		}
	}
	marker, err := attachStableTCPSource("/sys/fs/cgroup")
	if err != nil {
		var detail *sourceMarkerError
		if errors.As(err, &detail) {
			t.Log(detail.verifier)
		}
		t.Fatal(err)
	}
	defer marker.Close()
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if markerProbe(t, family, 0)&int(captureMark) == 0 {
			t.Fatal("new connection not marked before route selection")
		}
		if markerProbe(t, family, int(socketMark)) != int(socketMark) {
			t.Fatal("protected native socket was captured")
		}
	}
	script := `import socket,json
r=[]
for family,address in [(socket.AF_INET,('127.0.0.1',0)),(socket.AF_INET6,('::1',0))]:
 s=socket.socket(family,socket.SOCK_STREAM);s.setblocking(False);s.connect_ex(address);r.append(s.getsockopt(socket.SOL_SOCKET,socket.SO_MARK));s.close()
print(json.dumps(r))`
	child := exec.Command("python3", "-c", script)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	b, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged probe: %v %s", err, b)
	}
	var marks []uint32
	if json.Unmarshal(b, &marks) != nil || len(marks) != 2 {
		t.Fatal("bad unprivileged probe")
	}
	for _, m := range marks {
		if m&captureMark == 0 {
			t.Fatal("unprivileged application not marked")
		}
	}
	other := exec.Command("unshare", "--net", "python3", "-c", script)
	b, err = other.CombinedOutput()
	if err != nil {
		t.Fatalf("other namespace probe: %v %s", err, b)
	}
	if json.Unmarshal(b, &marks) != nil || len(marks) != 2 {
		t.Fatal("bad namespace probe")
	}
	for _, m := range marks {
		if m&captureMark != 0 {
			t.Fatal("marker escaped its network namespace")
		}
	}
	if err = marker.Close(); err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if markerProbe(t, family, 0)&int(captureMark) != 0 {
			t.Fatal("marker survived owner close")
		}
	}
}
