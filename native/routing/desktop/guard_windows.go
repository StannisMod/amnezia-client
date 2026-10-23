//go:build windows

package desktop

// A non-dynamic WFP session intentionally leaves these filters behind if the
// helper is killed. They last until explicit recovery or BFE restart (not a
// boot-time kill switch). Fixed private keys permit exact, transactional cleanup.
// SDK ABI/identifiers: microsoft/win32metadata, fwpmtypes.h and fwpmu.h.
// Lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpDisplay struct{ Name, Description *uint16 }
type wfpBlob struct {
	Size uint32
	Data *byte
}
type wfpValue struct {
	Type  uint32
	Value uintptr
}
type wfpCondition struct {
	Key   windows.GUID
	Match uint32
	Value wfpValue
}
type wfpAction struct {
	Type uint32
	Key  windows.GUID
}
type wfpSublayer struct {
	Key      windows.GUID
	Display  wfpDisplay
	Flags    uint32
	Provider *windows.GUID
	Data     wfpBlob
	Weight   uint16
}
type wfpFilter struct {
	Key             windows.GUID
	Display         wfpDisplay
	Flags           uint32
	Provider        *windows.GUID
	Data            wfpBlob
	Layer, Sublayer windows.GUID
	Weight          wfpValue
	Count           uint32
	Conditions      *wfpCondition
	Action          wfpAction
	_               [4]byte // align the SDK's UINT64/GUID context union
	Context         windows.GUID
	Reserved        *windows.GUID
	ID              uint64
	EffectiveWeight wfpValue
}

var (
	wfpDLL      = windows.NewLazySystemDLL("fwpuclnt.dll")
	guardKey    = windows.GUID{Data1: 0x82bec610, Data2: 0x54bb, Data3: 0x45a1, Data4: [8]byte{0x91, 0x6d, 0x62, 0x7b, 0xd9, 0xf2, 0x2c, 0x00}}
	guardLayers = []windows.GUID{
		{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}},
		{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}},
	}
	wfpApp        = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	wfpInterface  = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	wfpFlags      = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	wfpProtocol   = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	wfpLocalPort  = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	wfpRemotePort = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
)

const wfpNotFound windows.Errno = 0x80320003
const wfpSublayerNotFound windows.Errno = 0x80320007
const guardFilterCount = 10

//go:uintptrescapes
func wfpCall(name string, args ...uintptr) error {
	r, _, _ := wfpDLL.NewProc(name).Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(r))
	}
	return nil
}
func wfpOpen() (uintptr, error) {
	var handle uintptr
	err := wfpCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&handle)))
	return handle, err
}
func guardFilterKey(i int) windows.GUID { k := guardKey; k.Data4[7] = byte(i + 1); return k }
func guardDisplay() wfpDisplay {
	return wfpDisplay{Name: windows.StringToUTF16Ptr("Amnezia domain routing crash guard")}
}
func wfpTransaction(h uintptr, fn func() error) error {
	if err := wfpCall("FwpmTransactionBegin0", h, 0); err != nil {
		return err
	}
	defer wfpCall("FwpmTransactionAbort0", h)
	if err := fn(); err != nil {
		return err
	}
	return wfpCall("FwpmTransactionCommit0", h)
}

type windowsGuard struct{ handle uintptr }

func newWindowsGuard() (*windowsGuard, error) {
	h, err := wfpOpen()
	if err != nil {
		return nil, err
	}
	g := &windowsGuard{handle: h}
	exe, err := os.Executable()
	if err != nil {
		g.release()
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		g.release()
		return nil, err
	}
	var app *wfpBlob
	if err = wfpCall("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&app))); err != nil {
		g.release()
		return nil, err
	}
	defer wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&app)))
	err = wfpTransaction(h, func() error {
		// Already-existing keys are a crash/recovery conflict, never overwritten.
		sub := wfpSublayer{Key: guardKey, Display: guardDisplay(), Weight: 0xffff}
		if err := wfpCall("FwpmSubLayerAdd0", h, uintptr(unsafe.Pointer(&sub)), 0); err != nil {
			return err
		}
		for family := range guardLayers {
			base := family * 5
			if err := g.add(base, family, 0x1001, 0, nil); err != nil {
				return err
			} // block
			if err := g.add(base+1, family, 0x1002, 14, []wfpCondition{{Key: wfpApp, Value: wfpValue{Type: 12, Value: uintptr(unsafe.Pointer(app))}}}); err != nil {
				return err
			}
			// Loopback is native on both platforms, including IPC and local DNS.
			if err := g.add(base+2, family, 0x1002, 13, []wfpCondition{{Key: wfpFlags, Match: 6, Value: wfpValue{Type: 3, Value: 1}}}); err != nil {
				return err
			}
			local, remote := uintptr(68), uintptr(67)
			if family == 1 {
				local, remote = 546, 547
			}
			if err := g.add(base+3, family, 0x1002, 13, []wfpCondition{
				{Key: wfpProtocol, Value: wfpValue{Type: 1, Value: 17}},
				{Key: wfpLocalPort, Value: wfpValue{Type: 2, Value: local}},
				{Key: wfpRemotePort, Value: wfpValue{Type: 2, Value: remote}},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	runtime.KeepAlive(path)
	if err != nil {
		g.release()
		return nil, err
	}
	return g, nil
}

func (g *windowsGuard) add(key, family int, action uint32, weight uintptr, conditions []wfpCondition) error {
	f := wfpFilter{Key: guardFilterKey(key), Display: guardDisplay(), Layer: guardLayers[family], Sublayer: guardKey, Weight: wfpValue{Type: 1, Value: weight}, Action: wfpAction{Type: action}}
	if len(conditions) > 0 {
		f.Count = uint32(len(conditions))
		f.Conditions = &conditions[0]
	}
	var id uint64
	err := wfpCall("FwpmFilterAdd0", g.handle, uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(conditions)
	runtime.KeepAlive(f)
	return err
}

func (g *windowsGuard) allowCapture(luid uint64) error {
	return wfpTransaction(g.handle, func() error {
		for family := range guardLayers {
			if err := g.add(family*5+4, family, 0x1002, 12, []wfpCondition{{Key: wfpInterface, Value: wfpValue{Type: 4, Value: uintptr(unsafe.Pointer(&luid))}}}); err != nil {
				return err
			}
		}
		runtime.KeepAlive(&luid)
		return nil
	})
}
func (g *windowsGuard) release() {
	if g.handle != 0 {
		wfpCall("FwpmEngineClose0", g.handle)
		g.handle = 0
	}
}
func (g *windowsGuard) close() error { defer g.release(); return removeWindowsGuard(g.handle) }

func removeWindowsGuard(h uintptr) error {
	return wfpTransaction(h, func() error {
		for i := 0; i < guardFilterCount; i++ {
			key := guardFilterKey(i)
			if err := wfpCall("FwpmFilterDeleteByKey0", h, uintptr(unsafe.Pointer(&key))); err != nil && !errors.Is(err, wfpNotFound) {
				return err
			}
		}
		if err := wfpCall("FwpmSubLayerDeleteByKey0", h, uintptr(unsafe.Pointer(&guardKey))); err != nil && !errors.Is(err, wfpSublayerNotFound) {
			return err
		}
		return nil
	})
}

func recoverWindowsGuard() error {
	h, err := wfpOpen()
	if err != nil {
		return err
	}
	defer wfpCall("FwpmEngineClose0", h)
	return removeWindowsGuard(h)
}
