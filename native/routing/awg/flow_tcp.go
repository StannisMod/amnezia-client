package awg

import (
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Embedding the concrete connection preserves half-close and other TCP
// interfaces used by stream relays. Tracking never reconnects an application.
type flowTCPConn struct {
	*gonet.TCPConn
	owner    *FlowStack
	once     sync.Once
	closeErr error
}

func (c *flowTCPConn) Close() error {
	c.once.Do(func() {
		c.owner.state.Lock()
		delete(c.owner.tcpConnections, c)
		c.owner.state.Unlock()
		c.closeErr = c.TCPConn.Close()
	})
	return c.closeErr
}

func (s *FlowStack) trackTCP(conn *gonet.TCPConn) (net.Conn, error) {
	s.state.Lock()
	if s.closed {
		s.state.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	if s.tcpConnections == nil {
		s.tcpConnections = make(map[*flowTCPConn]struct{})
	}
	tracked := &flowTCPConn{TCPConn: conn, owner: s}
	s.tcpConnections[tracked] = struct{}{}
	s.state.Unlock()
	return tracked, nil
}

// Snapshot only: the future path-proof dispatcher must also enter the flow's
// active-operation guard before touching endpoints. No probe is sent here.
func (s *FlowStack) tcpConnectionsSnapshot() []*gonet.TCPConn {
	s.state.Lock()
	defer s.state.Unlock()
	if s.closed {
		return nil
	}
	connections := make([]*gonet.TCPConn, 0, len(s.tcpConnections))
	for conn := range s.tcpConnections {
		connections = append(connections, conn.TCPConn)
	}
	return connections
}
