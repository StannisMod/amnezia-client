package mobile

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestNativeConnectionOwnerLifecycle(t *testing.T) {
	request := &adapter.FindConnectionOwnerRequest{IpProtocol: 17, SourceAddress: "172.19.0.1", SourcePort: 42001, DestinationAddress: "198.18.0.1", DestinationPort: 53}
	want := &adapter.ConnectionOwner{UserId: 10264}
	calls := 0
	p := &Platform{fd: -1}
	if p.UsePlatformConnectionOwnerFinder() {
		t.Fatal("unsupported host advertised ownership")
	}
	if _, err := p.FindConnectionOwner(request); !errors.Is(err, unsupported) {
		t.Fatal(err)
	}
	p.hooks.FindConnectionOwner = func(got *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
		calls++
		if *got != *request {
			t.Fatal("original tuple changed", got)
		}
		return want, nil
	}
	if !p.UsePlatformConnectionOwnerFinder() {
		t.Fatal("native owner hook not advertised")
	}
	got, err := p.FindConnectionOwner(request)
	if err != nil || got != want || calls != 1 {
		t.Fatal(got, err, calls)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.FindConnectionOwner(request); !errors.Is(err, net.ErrClosed) || calls != 1 {
		t.Fatal("released native callback used", err, calls)
	}
}

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
