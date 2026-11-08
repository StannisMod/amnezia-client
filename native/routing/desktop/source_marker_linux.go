//go:build linux && !android

package desktop

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A link FD owns each attachment: closing it (including process death) removes
// only our program. Never fall back to persistent legacy PROG_ATTACH or replace
// somebody else's cgroup program. The namespace cookie excludes containers and
// other network namespaces below the same cgroup root.
type sourceMarker struct {
	links []int
	once  sync.Once
}

func (s *sourceMarker) Close() error {
	var first error
	s.once.Do(func() {
		for _, fd := range s.links {
			if err := unix.Close(fd); err != nil && first == nil {
				first = err
			}
		}
	})
	return first
}

// These layouts/opcodes are Linux UAPI, not private kernel/BTF structures.
type sourceInstruction struct {
	code, regs uint8
	off        int16
	imm        int32
}
type sourceProgramLoad struct {
	typeID, count        uint32
	insns, license       uint64
	logLevel, logSize    uint32
	log                  uint64
	kernelVersion, flags uint32
	name                 [16]byte
	ifindex, attach      uint32
}
type sourceLinkCreate struct{ program, target, attach, flags uint32 }
type sourceMarkerError struct {
	stage    string
	cause    error
	verifier string
}

func (e *sourceMarkerError) Error() string {
	return fmt.Sprintf("stable TCP source marker %s unavailable (%v)", e.stage, e.cause)
}
func (e *sourceMarkerError) Unwrap() error { return e.cause }

func sourceProgram(cookie uint64) []sourceInstruction {
	le := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
	ins := func(code, dst, src uint8, off int16, imm int32) sourceInstruction {
		regs := dst | src<<4
		if !le {
			regs = src | dst<<4
		}
		return sourceInstruction{code, regs, off, imm}
	}
	var code []sourceInstruction
	var exits []int
	add := func(op, dst, src uint8, off int16, imm int32) { code = append(code, ins(op, dst, src, off, imm)) }
	exitIf := func(op, dst, src uint8, imm int32) { exits = append(exits, len(code)); add(op, dst, src, 0, imm) }
	add(0xbf, 6, 1, 0, 0)  // r6 = socket-address context
	add(0x61, 2, 6, 32, 0) // UAPI type
	exitIf(0x56, 2, 0, unix.SOCK_STREAM)
	add(0x61, 2, 6, 36, 0) // UAPI protocol
	exitIf(0x56, 2, 0, unix.IPPROTO_TCP)
	add(0xbf, 1, 6, 0, 0)
	add(0x85, 0, 0, 0, 122) // get_netns_cookie(ctx)
	add(0x18, 7, 0, 0, int32(uint32(cookie)))
	add(0, 0, 0, 0, int32(cookie>>32))
	exitIf(0x5d, 0, 7, 0)
	args := func() {
		add(0xbf, 1, 6, 0, 0)
		add(0xb7, 2, 0, 0, unix.SOL_SOCKET)
		add(0xb7, 3, 0, 0, unix.SO_MARK)
		add(0xbf, 4, 10, 0, 0)
		add(0x07, 4, 0, 0, -4)
		add(0xb7, 5, 0, 0, 4)
	}
	add(0x62, 10, 0, -4, 0) // initialized stack value for getsockopt
	args()
	add(0x85, 0, 0, 0, 57) // getsockopt(ctx,SOL_SOCKET,SO_MARK,&mark,4)
	exitIf(0x55, 0, 0, 0)
	add(0x61, 2, 10, -4, 0)
	add(0xbf, 3, 2, 0, 0)
	add(0x54, 3, 0, 0, int32(socketMark))
	exitIf(0x56, 3, 0, 0) // protected native sockets keep their exemption
	add(0x44, 2, 0, 0, int32(captureMark))
	add(0x63, 10, 2, -4, 0)
	args()
	add(0x85, 0, 0, 0, 49) // setsockopt before connect's first route lookup
	end := len(code)
	add(0xb7, 0, 0, 0, 1)
	add(0x95, 0, 0, 0, 0) // preserve other cgroup ACL decisions
	for _, index := range exits {
		code[index].off = int16(end - index - 1)
	}
	return code
}

func currentNetworkCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var cookie uint64
	size := uint32(8)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, 71, uintptr(unsafe.Pointer(&cookie)), uintptr(unsafe.Pointer(&size)), 0) // SO_NETNS_COOKIE
	if errno != 0 {
		return 0, errno
	}
	if size != 8 || cookie == 0 {
		return 0, unix.EOPNOTSUPP
	}
	return cookie, nil
}

func attachStableTCPSource(path string) (*sourceMarker, error) {
	cgroup, err := os.Open(path)
	if err != nil {
		return nil, &sourceMarkerError{stage: "cgroup", cause: err}
	}
	defer cgroup.Close()
	var fs unix.Statfs_t
	if err = unix.Fstatfs(int(cgroup.Fd()), &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, &sourceMarkerError{stage: "cgroup v2", cause: unix.EOPNOTSUPP}
	}
	cookie, err := currentNetworkCookie()
	if err != nil {
		return nil, &sourceMarkerError{stage: "namespace cookie", cause: err}
	}
	marker := &sourceMarker{}
	ok := false
	defer func() {
		if !ok {
			marker.Close()
		}
	}()
	for _, attach := range []uint32{10, 11} { // CGROUP_INET4_CONNECT / INET6_CONNECT
		code := sourceProgram(cookie)
		license := []byte("GPL-3.0\x00") // no GPL-only helpers are used
		log := make([]byte, 8192)
		var pinned runtime.Pinner
		pinned.Pin(&code[0])
		pinned.Pin(&license[0])
		pinned.Pin(&log[0])
		attr := sourceProgramLoad{typeID: 18, count: uint32(len(code)), insns: uint64(uintptr(unsafe.Pointer(&code[0]))), license: uint64(uintptr(unsafe.Pointer(&license[0]))), logLevel: 1, logSize: uint32(len(log)), log: uint64(uintptr(unsafe.Pointer(&log[0]))), attach: attach}
		name := "amn_tcp4"
		if attach == 11 {
			name = "amn_tcp6"
		}
		copy(attr.name[:], name)
		program, _, errno := unix.Syscall(unix.SYS_BPF, 5, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr)) // PROG_LOAD
		pinned.Unpin()
		if errno != 0 {
			return nil, &sourceMarkerError{stage: "load", cause: errno, verifier: string(log)}
		}
		linkAttr := sourceLinkCreate{program: uint32(program), target: uint32(cgroup.Fd()), attach: attach}
		link, _, errno := unix.Syscall(unix.SYS_BPF, 28, uintptr(unsafe.Pointer(&linkAttr)), unsafe.Sizeof(linkAttr)) // LINK_CREATE only
		unix.Close(int(program))
		if errno != 0 {
			return nil, &sourceMarkerError{stage: "link", cause: errno}
		}
		marker.links = append(marker.links, int(link))
	}
	ok = true
	return marker, nil
}
