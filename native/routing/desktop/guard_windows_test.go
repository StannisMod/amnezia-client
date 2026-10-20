//go:build windows

package desktop

import (
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
