//go:build windows && amnezia_trust_probe

// Test-only native system-chain timing probe; never a production payload.
package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"time"
)

func main() {
	if runtime.GOOS != "windows" {
		panic("native Windows diagnostic required")
	}
	if len(os.Args) != 2 {
		panic("retained fixture CA path required")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		panic("missing retained certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	start := time.Now()
	_, err = certificate.Verify(x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"normal_windows_system_verifier": true, "elapsed_ms": time.Since(start).Milliseconds(),
		"error": fmt.Sprint(err), "scope": "native untrusted-root timing diagnostic; NOT TLS/VPN acceptance",
	})
	if err == nil {
		panic("fixture root unexpectedly trusted")
	}
}
