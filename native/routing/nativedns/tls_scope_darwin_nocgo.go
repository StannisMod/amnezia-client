//go:build darwin && !cgo

package nativedns

import "crypto/tls"

// The platform verifier may perform implicit issuer/revocation fetches. Without
// the native scoped-policy adapter, only an original explicit closed trust set
// is representable. Never silently use the online system verifier.
func scopedTLSConfig(config *tls.Config) (*tls.Config, error) {
	if config == nil || config.InsecureSkipVerify || config.ServerName == "" || config.RootCAs == nil {
		return nil, ErrScopeUnavailable
	}
	return config, nil
}
