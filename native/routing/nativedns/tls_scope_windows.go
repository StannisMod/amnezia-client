//go:build windows

package nativedns

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Default Windows verification can fetch CTLs, roots and AIA issuers using
// WinHTTP/default DNS, outside the selected transport (and recursively through
// this DNS frontend). Keep Go's normal CA/signature/name verification ENABLED,
// using a per-request snapshot of the original OS roots. Then ALSO require the
// native Windows chain/SSL policy, restricted to local/cached trust material.
// Missing roots/intermediates fail closed; no trust is guessed/downloaded.
func scopedTLSConfig(config *tls.Config) (*tls.Config, error) {
	if config == nil || config.InsecureSkipVerify || config.ServerName == "" {
		return nil, ErrScopeUnavailable
	}
	if config.RootCAs != nil {
		// An explicit original test trust policy is already a closed root set.
		return config, nil
	}
	roots, err := windowsRootSnapshot()
	if err != nil {
		return nil, err
	}
	selected := config.Clone()
	selected.RootCAs = roots
	previous := selected.VerifyConnection
	selected.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 {
			return ErrScopeUnavailable // Normal TLS verification must have run.
		}
		if err := verifyWindowsCachedPolicy(state.PeerCertificates, selected.ServerName); err != nil {
			return err
		}
		if previous != nil {
			return previous(state)
		}
		return nil
	}
	return selected, nil
}

func windowsRootSnapshot() (*x509.CertPool, error) {
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)
	pool := x509.NewCertPool() // Not SystemCertPool: that enables online platform verification again.
	count := 0
	var context *windows.CertContext
	for {
		// This API releases the previous context, including on end-of-store.
		context, err = windows.CertEnumCertificatesInStore(store, context)
		if context == nil {
			if !errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				return nil, fmt.Errorf("%w: enumerate original Windows roots: %v", ErrScopeUnavailable, err)
			}
			break
		}
		count++
		if count > 4096 {
			windows.CertFreeCertificateContext(context)
			return nil, ErrScopeUnavailable
		}
		certificate, parseErr := windowsCertificate(context)
		if parseErr == nil {
			pool.AddCert(certificate)
		}
	}
	if len(pool.Subjects()) == 0 {
		return nil, ErrScopeUnavailable
	}
	return pool, nil
}

func windowsCertificate(context *windows.CertContext) (*x509.Certificate, error) {
	if context == nil || context.EncodedCert == nil || context.Length == 0 || context.Length > 1024*1024 {
		return nil, ErrScopeUnavailable
	}
	// ParseCertificate retains its input; native contexts are independently freed.
	return x509.ParseCertificate(bytes.Clone(unsafe.Slice(context.EncodedCert, context.Length)))
}

const windowsScopedChainFlags = 0x00000004 | // CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
	0x00000100 | // CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
	0x80000000 | // CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY (no ignore/disable policy flags)
	0x00000080 // CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS

func verifyWindowsCachedPolicy(certificates []*x509.Certificate, serverName string) error {
	if len(certificates) == 0 || len(certificates) > 64 {
		return ErrScopeUnavailable
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var leaf *windows.CertContext
	for i, certificate := range certificates {
		if certificate == nil || len(certificate.Raw) == 0 {
			return ErrScopeUnavailable
		}
		context, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING,
			&certificate.Raw[0], uint32(len(certificate.Raw)))
		if err != nil {
			return err
		}
		err = windows.CertAddCertificateContextToStore(store, context, windows.CERT_STORE_ADD_ALWAYS, nil)
		if i == 0 && err == nil {
			leaf = context
			defer windows.CertFreeCertificateContext(leaf)
		} else {
			windows.CertFreeCertificateContext(context)
		}
		if err != nil {
			return err
		}
	}
	oid := []byte("1.3.6.1.5.5.7.3.1\x00") // Original TLS server-auth usage.
	oids := []*byte{&oid[0]}
	parameters := windows.CertChainPara{}
	parameters.Size = uint32(unsafe.Sizeof(parameters))
	parameters.RequestedUsage.Type = windows.USAGE_MATCH_TYPE_OR
	parameters.RequestedUsage.Usage.Length = 1
	parameters.RequestedUsage.Usage.UsageIdentifiers = &oids[0]
	var chain *windows.CertChainContext
	err = windows.CertGetCertificateChain(0, leaf, nil, store, &parameters, windowsScopedChainFlags, 0, &chain)
	runtime.KeepAlive(oids)
	runtime.KeepAlive(oid)
	if err != nil {
		return err
	}
	if chain == nil {
		return ErrScopeUnavailable
	}
	defer windows.CertFreeCertificateChain(chain)
	name, err := windows.UTF16PtrFromString(strings.TrimSuffix(serverName, "."))
	if err != nil {
		return err
	}
	accept := func(candidate *windows.CertChainContext) bool {
		if candidate == nil || candidate.TrustStatus.ErrorStatus != 0 ||
			candidate.ChainCount == 0 || candidate.ChainCount > 32 || candidate.Chains == nil {
			return false
		}
		extra := windows.SSLExtraCertChainPolicyPara{AuthType: windows.AUTHTYPE_SERVER, ServerName: name}
		extra.Size = uint32(unsafe.Sizeof(extra))
		policy := windows.CertChainPolicyPara{ExtraPolicyPara: windows.Pointer(unsafe.Pointer(&extra))}
		policy.Size = uint32(unsafe.Sizeof(policy))
		status := windows.CertChainPolicyStatus{}
		status.Size = uint32(unsafe.Sizeof(status))
		if windows.CertVerifyCertificateChainPolicy(windows.CERT_CHAIN_POLICY_SSL, candidate, &policy, &status) != nil ||
			status.Error != 0 {
			return false
		}
		// Retain Go's defense against native custom-curve chain spoofing:
		// independently parse and verify every native returned chain edge.
		for _, simple := range unsafe.Slice(candidate.Chains, candidate.ChainCount) {
			if simple == nil || simple.NumElements == 0 || simple.NumElements > 64 || simple.Elements == nil {
				return false
			}
			var child *x509.Certificate
			for _, element := range unsafe.Slice(simple.Elements, simple.NumElements) {
				if element == nil {
					return false
				}
				parent, err := windowsCertificate(element.CertContext)
				if err != nil || (child != nil && child.CheckSignatureFrom(parent) != nil) {
					return false
				}
				child = parent
			}
		}
		return true
	}
	if accept(chain) {
		return nil
	}
	if chain.LowerQualityChainCount > 64 {
		return ErrScopeUnavailable
	}
	if chain.LowerQualityChains != nil {
		for _, lower := range unsafe.Slice(chain.LowerQualityChains, chain.LowerQualityChainCount) {
			if accept(lower) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: native cached TLS chain/SSL policy refused", ErrScopeUnavailable)
}
