package socketcontrol

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type raw struct{ err error }

func (r raw) Control(f func(uintptr)) error {
	if r.err != nil {
		return r.err
	}
	f(7)
	return nil
}
func (raw) Read(func(uintptr) bool) error  { panic("unexpected Read") }
func (raw) Write(func(uintptr) bool) error { panic("unexpected Write") }

func TestPolicyAndErrors(t *testing.T) {
	var c Controller
	bindError := errors.New("bind failure")
	bind := func(fd uintptr, index uint32, blocked bool) error {
		if fd != 7 || index != 2 || !blocked {
			t.Fatal("wrong socket scope")
		}
		return bindError
	}
	if c.Start(0, true) > 0 {
		t.Fatal("accepted missing scope")
	}
	if err := c.Control(raw{}, bind); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	h := c.Start(2, true)
	if h <= 0 || c.Start(3, false) > 0 {
		t.Fatal("ownership")
	}
	if err := c.Control(raw{}, bind); !errors.Is(err, bindError) {
		t.Fatal(err)
	}
	rawError := errors.New("raw control failure")
	if err := c.Control(raw{rawError}, bind); !errors.Is(err, rawError) {
		t.Fatal(err)
	}
	c.Update(h, 0)
	if err := c.Control(raw{}, bind); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	c.Stop(h)
	next := c.Start(2, true)
	if next <= h {
		t.Fatal("reused handle")
	}
	c.Update(h, 0)
	c.Stop(h)
	if err := c.Control(raw{}, bind); !errors.Is(err, bindError) {
		t.Fatal("stale handle changed next run", err)
	}
	c.Stop(next)
}

func TestStopJoinsCallback(t *testing.T) {
	var c Controller
	h := c.Start(2, false)
	entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.Control(raw{}, func(_ uintptr, index uint32, blocked bool) error {
			if index != 2 || blocked {
				t.Error("ON policy changed")
			}
			close(entered)
			<-release
			return nil
		}); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	go func() { c.Stop(h); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned before callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop did not join")
	}
	wg.Wait()
}
