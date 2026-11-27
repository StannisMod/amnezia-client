// Package socketcontrol owns the single native Xray dialer policy. Callbacks
// hold a read lease; Stop joins them and stale handles cannot alter a later run.
package socketcontrol

import (
	"errors"
	"sync"
	"syscall"
)

var ErrUnavailable = errors.New("native socket scope unavailable")

type Controller struct {
	mu           sync.RWMutex
	next, active int64
	index        uint32
	blockIPv6    bool
}

func (c *Controller) Start(index uint32, blockIPv6 bool) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != 0 || index == 0 {
		return -1
	}
	c.next++
	c.active, c.index, c.blockIPv6 = c.next, index, blockIPv6
	return c.active
}

// Zero suspends new dials instead of falling back to the default route.
func (c *Controller) Update(handle int64, index uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if handle > 0 && c.active == handle {
		c.index = index
	}
}

func (c *Controller) Stop(handle int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if handle > 0 && c.active == handle {
		c.active, c.index = 0, 0
	}
}

func (c *Controller) Control(conn syscall.RawConn, bind func(uintptr, uint32, bool) error) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.active == 0 || c.index == 0 {
		return ErrUnavailable
	}
	var bindError error
	if err := conn.Control(func(fd uintptr) {
		bindError = bind(fd, c.index, c.blockIPv6)
	}); err != nil {
		return err
	}
	return bindError
}
