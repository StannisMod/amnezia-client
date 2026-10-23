package awg

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Configuration and socket-open failures happen after the reader goroutine
// exists. They must unwind without waiting forever for its initial packet.
func TestConfiguredDeviceFailedStartRecovery(t *testing.T) {
	private, _ := keypair(t)
	_, public := keypair(t)
	config := Config{Address: []netip.Addr{netip.MustParseAddr("10.77.0.1")}, PrivateKey: private, PublicKey: public,
		Endpoint: netip.MustParseAddrPort("127.0.0.1:9"), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	var lc net.ListenConfig
	for _, stage := range []string{"UAPI", "underlay"} {
		t.Run(stage, func(t *testing.T) {
			failed := config
			listen := lc.ListenPacket
			if stage == "UAPI" {
				failed.Parameters = map[string]string{"s4": "invalid"}
			} else {
				listen = func(context.Context, string, string) (net.PacketConn, error) {
					return nil, errors.New("controlled socket failure")
				}
			}
			done := make(chan error, 1)
			go func() {
				transport, err := New(context.Background(), failed, listen)
				if transport != nil {
					transport.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid startup succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("failed startup blocked reader cleanup")
			}
			transport, err := New(context.Background(), config, lc.ListenPacket)
			if err != nil {
				t.Fatal("valid startup after failure", err)
			}
			if err = transport.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
