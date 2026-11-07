//go:build (linux && !android) || windows

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
)

type recoveryRequest struct {
	Type    string `json:"type"`
	ID      uint64 `json:"request_id"`
	Address string `json:"address,omitempty"`
}

// The command may change only a numeric address of the already configured
// peer, never its identity, keys, tunnel addresses, policy or endpoint port.
func parseRecoveryRequest(line string, port uint16) (recoveryRequest, netip.AddrPort, error) {
	var request recoveryRequest
	invalid := errors.New("invalid underlay recovery command")
	if len(line) > 2048 {
		return request, netip.AddrPort{}, invalid
	}
	d := json.NewDecoder(strings.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request.Type != "refresh_underlay" || request.ID == 0 || request.ID > 1<<53-1 {
		return request, netip.AddrPort{}, invalid
	}
	if request.Address == "" {
		return request, netip.AddrPort{}, nil
	}
	address, err := netip.ParseAddr(request.Address)
	if err != nil || port == 0 || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return request, netip.AddrPort{}, invalid
	}
	return request, netip.AddrPortFrom(address.Unmap(), port), nil
}
