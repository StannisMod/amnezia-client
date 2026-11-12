package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

func configIPv6JournalOK(value *configIPv6Journal) bool {
	if value == nil {
		return true
	}
	prefix, err := netip.ParsePrefix(value.CIDR)
	if err != nil || prefix.Bits() != 64 || !prefix.Addr().Is6() || !clientIPv6OK(prefix.Addr().String()) || prefix.String() != value.CIDR {
		return false
	}
	if value.WasPresent && (value.AddIntent || value.Ambiguous) {
		return false
	}
	if value.Ambiguous && (!value.AddIntent || value.Applied) {
		return false
	}
	return !value.Applied || value.WasPresent || value.AddIntent
}
func protocolInterface(container string) (string, error) {
	switch container {
	case "amnezia-wireguard":
		return "wg0", nil
	case "amnezia-awg2":
		return "awg0", nil
	default:
		return "", errors.New("unsupported protocol container")
	}
}
func readProtocolIPv6(container, cidr string, requireReady bool) (bool, error) {
	target, err := netip.ParsePrefix(cidr)
	if err != nil || !configIPv6JournalOK(&configIPv6Journal{CIDR: cidr}) {
		return false, errors.New("invalid server IPv6 address")
	}
	name, err := protocolInterface(container)
	if err != nil {
		return false, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, errors.New("protocol interface unavailable")
	}
	if requireReady && (iface.MTU < 1280 || iface.Flags&net.FlagUp == 0) {
		return false, errors.New("protocol interface cannot carry IPv6")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false, errors.New("cannot read protocol addresses")
	}
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err != nil || prefix.Addr() != target.Addr() {
			continue
		}
		if prefix != target {
			return false, errConfigConflict
		}
		return true, nil
	}
	return false, nil
}
func protocolIPv6Present(container, cidr string) (bool, error) {
	return readProtocolIPv6(container, cidr, true)
}
func changeProtocolIPv6(container, cidr string, add bool) error {
	name, err := protocolInterface(container)
	if err != nil {
		return err
	}
	action := "del"
	if add {
		action = "add"
	}
	args := []string{"-6", "address", action, cidr, "dev", name}
	if add {
		args = append(args, "nodad")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := protocolCommand(ctx, "ip", args...).Run(); err != nil {
		return errors.New("cannot change protocol IPv6 address")
	}
	return nil
}
func applyProtocolIPv6(transaction *configTransaction, container string) error {
	meta := transaction.journal.IPv6
	if meta == nil {
		return nil
	}
	if meta.Ambiguous {
		return errConfigConflict
	}
	present, err := protocolIPv6Present(container, meta.CIDR)
	if err != nil {
		return err
	}
	if meta.WasPresent {
		if !present {
			return errConfigConflict
		}
		return nil
	}
	if present {
		if !meta.AddIntent {
			return errConfigConflict
		}
		return nil
	}
	if !meta.AddIntent {
		meta.AddIntent = true
		if err := transaction.saveJournal(); err != nil {
			return err
		}
	}
	if err := changeProtocolIPv6(container, meta.CIDR, true); err != nil {
		// A non-successful command with an observed address has uncertain ownership.
		// Preserve it and require explicit recovery instead of deleting another actor's address.
		found, observeErr := readProtocolIPv6(container, meta.CIDR, false)
		if found || observeErr != nil {
			meta.Ambiguous = true
			if journalErr := transaction.saveJournal(); journalErr != nil {
				return journalErr
			}
		}
		return err
	}
	return nil
}
func rollbackProtocolIPv6(transaction *configTransaction, container string) error {
	meta := transaction.journal.IPv6
	if meta == nil || meta.WasPresent || !meta.AddIntent {
		return nil
	}
	if meta.Ambiguous {
		return errConfigConflict
	}
	present, err := readProtocolIPv6(container, meta.CIDR, false)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := changeProtocolIPv6(container, meta.CIDR, false); err != nil {
		if stillPresent, observeErr := readProtocolIPv6(container, meta.CIDR, false); observeErr == nil && !stillPresent {
			return nil
		}
		return err
	}
	return nil
}
func verifyIPv6Commit(transaction *configTransaction, container string) error {
	meta := transaction.journal.IPv6
	if meta == nil {
		return nil
	}
	if !meta.Applied || meta.Ambiguous {
		return errors.New("IPv6 configuration has not been applied")
	}
	present, err := protocolIPv6Present(container, meta.CIDR)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("server IPv6 address missing")
	}
	return nil
}

func configIPv6PlanMatches(journal configJournal) bool {
	if journal.IPv6 == nil {
		return true
	}
	plan, err := planIPv6Config(journal.Original, journal.IPv6.CIDR)
	return err == nil && configHash(plan.Config) == journal.CandidateHash
}
