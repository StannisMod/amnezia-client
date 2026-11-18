//go:build !android && !ios

package main

import (
	"strconv"
	"strings"
)

// Never serialize UAPI: it contains private/public keys and endpoint identity.
func publicPeerCounters(status string) map[string]int64 {
	result := make(map[string]int64)
	for _, line := range strings.Split(status, "\n") {
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec", "last_handshake_time_nsec", "rx_bytes", "tx_bytes":
			if value, err := strconv.ParseInt(raw, 10, 64); err == nil && value >= 0 {
				result["peer_"+key] = value
			}
		}
	}
	return result
}
