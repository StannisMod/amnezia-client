package main

import (
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// A plan is pure: no server state changes until a separate transaction commits it.
type ipv6ConfigPlan struct {
	Config      []byte
	Assignments map[string]string
}

func planIPv6Config(configuration []byte, serverCIDR string) (ipv6ConfigPlan, error) {
	reject := func() (ipv6ConfigPlan, error) {
		return ipv6ConfigPlan{}, errors.New("ambiguous or unsupported IPv6 migration configuration")
	}
	server, err := netip.ParsePrefix(serverCIDR)
	if err != nil || server.Bits() != 64 || !clientIPv6OK(server.Addr().String()) || serverCIDR != server.String() || server.Addr().Is4() {
		return reject()
	}
	if len(configuration) == 0 || len(configuration) > 4<<20 || !utf8.Valid(configuration) || strings.ContainsRune(string(configuration), '\x00') {
		return reject()
	}
	lines := strings.Split(string(configuration), "\n")
	type peer struct {
		key     string
		allowed int
	}
	peers := []peer{}
	section := ""
	addressLine, interfaceCount := -1, 0
	for index, original := range lines {
		line := strings.TrimSpace(strings.SplitN(original, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return reject()
			}
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			switch section {
			case "Interface":
				interfaceCount++
				if interfaceCount != 1 || len(peers) != 0 {
					return reject()
				}
			case "Peer":
				if interfaceCount != 1 {
					return reject()
				}
				peers = append(peers, peer{allowed: -1})
			default:
				return reject()
			}
			continue
		}
		field := strings.SplitN(line, "=", 2)
		if len(field) != 2 || section == "" {
			return reject()
		}
		name, value := strings.TrimSpace(field[0]), strings.TrimSpace(field[1])
		if section == "Interface" && name == "Address" {
			if addressLine != -1 {
				return reject()
			}
			addressLine = index
		}
		if section == "Peer" {
			current := &peers[len(peers)-1]
			if name == "PublicKey" {
				if current.key != "" || !keyOK(value) {
					return reject()
				}
				current.key = value
			}
			if name == "AllowedIPs" {
				if current.allowed != -1 {
					return reject()
				}
				current.allowed = index
			}
		}
	}
	if interfaceCount != 1 || addressLine < 0 {
		return reject()
	}
	values := func(line string) []string {
		return strings.Split(strings.SplitN(strings.SplitN(line, "#", 2)[0], "=", 2)[1], ",")
	}
	appendValue := func(line, value string) string {
		parts := strings.SplitN(line, "#", 2)
		prefix := strings.TrimRight(parts[0], " \t\r")
		return prefix + ", " + value + line[len(prefix):]
	}
	hasServer := false
	for _, value := range values(lines[addressLine]) {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return reject()
		}
		if prefix.Addr().Is6() {
			// Existing server IPv6 must be deliberately reused, never silently replaced.
			if prefix != server || hasServer {
				return reject()
			}
			hasServer = true
		}
	}
	if !hasServer {
		lines[addressLine] = appendValue(lines[addressLine], serverCIDR)
	}
	assignments := map[string]string{}
	occupied := map[netip.Addr]bool{server.Addr(): true}
	occupiedIPv4 := map[netip.Addr]bool{}
	for _, current := range peers {
		if current.key == "" || current.allowed < 0 {
			return reject()
		}
		if _, exists := assignments[current.key]; exists {
			return reject()
		}
		var ipv4, ipv6 netip.Addr
		for _, value := range values(lines[current.allowed]) {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return reject()
			}
			address := prefix.Addr()
			if address.Is4() && prefix.Bits() == 32 {
				if ipv4.IsValid() || !address.IsGlobalUnicast() {
					return reject()
				}
				ipv4 = address
			} else if address.Is6() {
				if prefix.Bits() != 128 || ipv6.IsValid() || !clientIPv6OK(address.String()) || !server.Masked().Contains(address) {
					return reject()
				}
				ipv6 = address
			}
		}
		if !ipv4.IsValid() || occupiedIPv4[ipv4] {
			return reject()
		}
		occupiedIPv4[ipv4] = true
		if !ipv6.IsValid() {
			raw := server.Masked().Addr().As16()
			raw[10], raw[11] = 0, 1
			v4 := ipv4.As4()
			copy(raw[12:], v4[:])
			ipv6 = netip.AddrFrom16(raw)
			lines[current.allowed] = appendValue(lines[current.allowed], ipv6.String()+"/128")
		}
		if occupied[ipv6] {
			return reject()
		}
		occupied[ipv6] = true
		assignments[current.key] = ipv6.String()
	}
	return ipv6ConfigPlan{Config: []byte(strings.Join(lines, "\n")), Assignments: assignments}, nil
}
