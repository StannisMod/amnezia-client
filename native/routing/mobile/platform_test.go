package mobile

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type inventoryManager struct {
	adapter.NetworkManager
	called bool
	err    error
}

func (m *inventoryManager) UpdateInterfaces() error { m.called = true; return m.err }

func TestStaticDesktopInventoryIsInitialized(t *testing.T) {
	want := errors.New("native inventory unavailable")
	manager := &inventoryManager{err: want}
	p := &Platform{hooks: Hooks{InitializeInterfaces: true}}
	if err := p.Initialize(manager); !errors.Is(err, want) || !manager.called {
		t.Fatal("desktop source inventory was not initialized", err)
	}
	manager.called = false
	p.hooks.InitializeInterfaces = false
	if err := p.Initialize(manager); err != nil || manager.called {
		t.Fatal("mobile host inventory ownership changed", err)
	}
}
