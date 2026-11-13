package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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

// A default route and installed NAT rules are not evidence of Internet egress.
// Verify a TLS-authenticated response over IPv6, bound to the tunnel source so
// this also exercises the source-prefix NAT rather than only the bridge IP.
// Public endpoints: https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/
func probeIPv6HTTPS(ctx context.Context, source netip.Addr, endpoint netip.AddrPort, serverName, path string, roots *x509.CertPool) error {
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("IPv6 egress probe requires a deadline")
	}
	if !source.Is6() || source.Is4In6() || source.Zone() != "" || !endpoint.Addr().Is6() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 || serverName == "" {
		return errors.New("invalid IPv6 egress probe")
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(source.AsSlice())}, Timeout: 4 * time.Second}
	transport := &http.Transport{
		Proxy: nil, // Never consult HTTP(S)_PROXY or bypass the measured source path.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", endpoint.String())
		},
		TLSClientConfig:        &tls.Config{ServerName: serverName, RootCAs: roots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 8192,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("egress redirects forbidden") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+serverName+path+"?name=.&type=NS", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/dns-json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("authenticated IPv6 egress unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("unexpected IPv6 egress response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return errors.New("invalid IPv6 egress response")
	}
	var answer struct {
		Status   *int
		Question []struct {
			Name string
			Type int
		}
		Answer []struct {
			Type int
			Data string
		}
	}
	if json.Unmarshal(raw, &answer) != nil || answer.Status == nil || *answer.Status != 0 || len(answer.Question) != 1 || answer.Question[0].Name != "." || answer.Question[0].Type != 2 || len(answer.Answer) == 0 || len(answer.Answer) > 64 {
		return errors.New("IPv6 egress response did not answer the probe")
	}
	for _, record := range answer.Answer {
		if record.Type == 2 && record.Data != "" {
			return nil
		}
	}
	return errors.New("IPv6 egress response lacks root nameservers")
}

func verifyConfigIPv6Egress(transaction *configTransaction, container string) error {
	// This rechecks journal, native/file identity, current IPv6 address, and
	// verified forwarding under the same protocol lock before measuring egress.
	if err := prepareConfigForwarding(transaction, container); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(transaction.journal.IPv6.CIDR)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Independent providers avoid making a single service outage equivalent to
	// absence of IPv6. Only a root-NS probe is sent, never user DNS queries.
	// https://developers.google.com/speed/public-dns/docs/doh
	for _, target := range []struct{ address, name, path string }{
		{"2606:4700:4700::1111", "cloudflare-dns.com", "/dns-query"},
		{"2001:4860:4860::8888", "dns.google", "/resolve"},
	} {
		attempt, stop := context.WithTimeout(ctx, 5*time.Second)
		err = probeIPv6HTTPS(attempt, prefix.Addr(), netip.AddrPortFrom(netip.MustParseAddr(target.address), 443), target.name, target.path, nil)
		stop()
		if err == nil {
			return nil
		}
	}
	return errors.New("IPv6 Internet egress not verified")
}
