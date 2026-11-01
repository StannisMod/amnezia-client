//go:build windows

package desktop

import (
	"os"
	"testing"
	"unsafe"
)

func TestWFPGuardABI(t *testing.T) {
	// Windows amd64 SDK layouts. These are API ABI assertions, not snapshots
	// of policy implementation. Native acceptance additionally calls each API.
	if unsafe.Sizeof(wfpFilter{}) != 200 || unsafe.Offsetof(wfpFilter{}.Action) != 128 || unsafe.Offsetof(wfpFilter{}.ID) != 176 || unsafe.Sizeof(wfpSublayer{}) != 72 || unsafe.Sizeof(wfpCondition{}) != 40 {
		t.Fatalf("WFP ABI mismatch: filter=%d action=%d id=%d sublayer=%d condition=%d", unsafe.Sizeof(wfpFilter{}), unsafe.Offsetof(wfpFilter{}.Action), unsafe.Offsetof(wfpFilter{}.ID), unsafe.Sizeof(wfpSublayer{}), unsafe.Sizeof(wfpCondition{}))
	}
}

func TestNativeWFPGuardOutlivesSession(t *testing.T) {
	if os.Getenv("AMNEZIA_NATIVE_WFP_TEST") != "1" {
		t.Skip("requires a disposable elevated Windows host")
	}
	defer func() {
		if err := recoverWindowsGuard(); err != nil {
			t.Error(err)
		}
	}()
	g, err := newWindowsGuard()
	if err != nil {
		t.Fatal(err)
	}
	g.release() // simulate the creating session/process disappearing
	h, err := wfpOpen()
	if err != nil {
		t.Fatal(err)
	}
	defer wfpCall("FwpmEngineClose0", h)
	for _, i := range []int{0, 1, 2, 3, 5, 6, 7, 8} {
		key := guardFilterKey(i)
		var filter *wfpFilter
		if err := wfpCall("FwpmFilterGetByKey0", h, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&filter))); err != nil {
			t.Fatal("guard did not survive owner close", err)
		}
		if filter.Sublayer != guardKey {
			t.Fatal("foreign filter under private guard key")
		}
		wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&filter)))
	}
	if second, err := newWindowsGuard(); err == nil {
		second.close()
		t.Fatal("live/stale guard was overwritten")
	}
}
