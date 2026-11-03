//go:build race && arm64

package awg

import (
	"testing"

	routingSync "github.com/sagernet/gvisor/pkg/sync"
	legacySync "gvisor.dev/gvisor/pkg/sync"
)

// The pinned ARM64 race assembly loads new into R1, overwriting old, while
// its store consumes R2. This reproduces that defect without network timing.
func TestGVisorRaceCAS(t *testing.T) {
	for name, cas := range map[string]func(*uintptr, uintptr, uintptr) bool{
		"awg-flow-stack": legacySync.RaceUncheckedAtomicCompareAndSwapUintptr,
		"routing-stack":  routingSync.RaceUncheckedAtomicCompareAndSwapUintptr,
	} {
		t.Run(name, func(t *testing.T) {
			var value uintptr = 10
			if !cas(&value, 10, 20) || value != 20 {
				t.Fatalf("CAS failed to swap expected value: got %d, want 20", value)
			}
			if cas(&value, 10, 30) || value != 20 {
				t.Fatalf("CAS mutated a mismatched value: got %d, want 20", value)
			}
			if !cas(&value, 20, 40) || value != 40 {
				t.Fatalf("CAS failed to swap expected value: got %d, want 40", value)
			}
		})
	}
}
