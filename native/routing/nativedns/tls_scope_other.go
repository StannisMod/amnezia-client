//go:build !windows && !darwin

package nativedns

import "crypto/tls"

func scopedTLSConfig(config *tls.Config) (*tls.Config, error) { return config, nil }
