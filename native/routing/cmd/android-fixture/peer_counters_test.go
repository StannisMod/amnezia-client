//go:build !android && !ios

package main

import "testing"

func TestPublicPeerCountersExcludeIdentityAndInvalidValues(t *testing.T) {
	result := publicPeerCounters("private_key=secret\npublic_key=secret\nendpoint=private\nrx_bytes=42\ntx_bytes=-1\nlast_handshake_time_sec=123\nlast_handshake_time_nsec=invalid\n")
	if len(result) != 2 || result["peer_rx_bytes"] != 42 || result["peer_last_handshake_time_sec"] != 123 {
		t.Fatalf("incorrect public counters: %v", result)
	}
}
