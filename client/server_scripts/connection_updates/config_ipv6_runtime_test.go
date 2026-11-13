package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigIPv6JournalRejectsImpossibleOwnership(t *testing.T) {
	for _, value := range []configIPv6Journal{
		{CIDR: "fd77::1/64"}, {CIDR: "fd77::1/64", WasPresent: true},
		{CIDR: "fd77::1/64", AddIntent: true}, {CIDR: "fd77::1/64", AddIntent: true, Applied: true},
		{CIDR: "fd77::1/64", WasPresent: true, Applied: true}, {CIDR: "fd77::1/64", AddIntent: true, Ambiguous: true},
	} {
		if !configIPv6JournalOK(&value) {
			t.Fatal("valid ownership rejected", value)
		}
	}
	for _, value := range []configIPv6Journal{
		{CIDR: "fd77::1/128"}, {CIDR: "10.8.0.1/24"}, {CIDR: "fe80::1/64"}, {CIDR: "FD77::1/64"},
		{CIDR: "fd77::1/64", WasPresent: true, AddIntent: true}, {CIDR: "fd77::1/64", Ambiguous: true},
		{CIDR: "fd77::1/64", Applied: true}, {CIDR: "fd77::1/64", AddIntent: true, Ambiguous: true, Applied: true},
	} {
		if configIPv6JournalOK(&value) {
			t.Fatal("impossible ownership accepted", value)
		}
	}
}

func TestConfigIPv6JournalBindsAddressToExactMigrationPlan(t *testing.T) {
	original := []byte(migrationConfig())
	plan, err := planIPv6Config(original, "fd77::1/64")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	transaction, err := beginPreparedConfigTransaction(path, original, plan.Config, func(journal *configJournal) error {
		journal.IPv6 = &configIPv6Journal{CIDR: "fd77::1/64", WasPresent: true}
		journal.NativeOriginal = []byte("synthetic native configuration")
		journal.NativeHash = configHash(journal.NativeOriginal)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	transaction.close()
	resumed, err := resumeConfigTransaction(path)
	if err != nil {
		t.Fatal(err)
	}
	resumed.close()
	raw, err := os.ReadFile(path + ".amnezia-journal")
	if err != nil {
		t.Fatal(err)
	}
	var journal configJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatal(err)
	}
	journal.IPv6.CIDR = "fd88::1/64"
	raw, err = json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".amnezia-journal", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if resumed, err := resumeConfigTransaction(path); err == nil {
		resumed.close()
		t.Fatal("address mutation detached from plan accepted")
	}
	assertConfig(t, path, plan.Config)
}

func TestIPv6EgressUsesAuthenticatedBoundIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal("local IPv6 required for egress regression", err)
	}
	var requests atomic.Int64
	var mode atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || netip.MustParseAddr(address) != netip.IPv6Loopback() {
			t.Error("wrong probe source", r.RemoteAddr)
		}
		if r.URL.Path != "/dns-query" || r.URL.Query().Get("name") != "." || r.URL.Query().Get("type") != "NS" {
			t.Error("unexpected probe request")
		}
		requests.Add(1)
		if mode.Load() == 1 {
			http.Redirect(w, r, "https://forbidden.invalid/", http.StatusFound)
			return
		}
		if mode.Load() == 2 {
			io.WriteString(w, `{"Status":0,"Question":[{"name":"other.test.","type":2}],"Answer":[{"type":2,"data":"ns.test."}]}`)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		io.WriteString(w, `{"Status":0,"Question":[{"name":".","type":2}],"Answer":[{"type":2,"data":"a.root-servers.net."}]}`)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	name := server.Certificate().DNSNames[0]
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	source := netip.IPv6Loopback()
	if err := probeIPv6HTTPS(ctx, source, endpoint, name, "/dns-query", roots); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("probe bypassed controlled IPv6 server")
	}
	if err := probeIPv6HTTPS(ctx, source, endpoint, "untrusted.invalid", "/dns-query", roots); err == nil {
		t.Fatal("wrong TLS identity accepted")
	}
	for _, bad := range []int64{1, 2} {
		mode.Store(bad)
		if err := probeIPv6HTTPS(ctx, source, endpoint, name, "/dns-query", roots); err == nil {
			t.Fatal("redirect or unrelated response accepted", bad)
		}
	}
	if requests.Load() != 3 {
		t.Fatal("unexpected redirect/DNS fallback traffic", requests.Load())
	}
	if err := probeIPv6HTTPS(context.Background(), source, endpoint, name, "/dns-query", roots); err == nil {
		t.Fatal("unbounded measurement accepted")
	}
	if err := probeIPv6HTTPS(ctx, netip.MustParseAddr("127.0.0.1"), endpoint, name, "/dns-query", roots); err == nil {
		t.Fatal("IPv4 source accepted")
	}
}
