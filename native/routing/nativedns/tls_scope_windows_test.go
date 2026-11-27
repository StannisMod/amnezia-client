//go:build windows

package nativedns

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestScopedWindowsTLSKeepsDefaultAndNativeVerification(t *testing.T) {
	base := &tls.Config{ServerName: "selected.invalid", MinVersion: tls.VersionTLS12}
	selected, err := scopedTLSConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if selected == base || selected.RootCAs == nil || selected.VerifyConnection == nil ||
		selected.InsecureSkipVerify || selected.ServerName != base.ServerName ||
		selected.MinVersion != base.MinVersion || base.RootCAs != nil || base.VerifyConnection != nil {
		t.Fatal("scoped system trust changed identity, bypassed default verification or mutated its template")
	}
	if selected.VerifyConnection(tls.ConnectionState{}) == nil {
		t.Fatal("native policy callback accepted absent normal verified chains")
	}
	if selected.VerifyConnection(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}) == nil {
		t.Fatal("native policy callback accepted absent peer certificates")
	}
	if windowsScopedChainFlags != 0x80000184 {
		t.Fatal("native trust enabled implicit retrieval or lost lower-quality chain validation")
	}
}

func TestScopedWindowsTLSRetainsExplicitOriginalTrustAndRefusesBypass(t *testing.T) {
	roots := x509.NewCertPool()
	base := &tls.Config{ServerName: "selected.invalid", RootCAs: roots, MinVersion: tls.VersionTLS12}
	selected, err := scopedTLSConfig(base)
	if err != nil || selected != base || selected.RootCAs != roots || selected.InsecureSkipVerify {
		t.Fatal("explicit original trust was substituted", err)
	}
	for _, invalid := range []*tls.Config{
		nil, {}, {ServerName: "selected.invalid", InsecureSkipVerify: true},
		{ServerName: "selected.invalid", RootCAs: roots, InsecureSkipVerify: true},
	} {
		if _, err := scopedTLSConfig(invalid); err == nil {
			t.Fatal("invalid/bypassed selected trust was accepted")
		}
	}
}
