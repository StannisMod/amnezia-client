package awg

import (
	"encoding/json"
	"errors"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// Keepalive preserves AWG 3.1's single value or inclusive range in seconds.
// Its zero value means disabled. Numeric JSON remains accepted for older hosts.
type Keepalive string

func ParseKeepalive(value string) (Keepalive, error) {
	var interval device.UintRange
	if err := interval.FromString(value); err != nil {
		return "", errors.New("invalid AWG keepalive")
	}
	return Keepalive(value), nil
}

func (k Keepalive) String() string {
	if k == "" {
		return "0"
	}
	return string(k)
}

func (k *Keepalive) UnmarshalJSON(raw []byte) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		// ParseKeepalive rejects fractions, signs, exponents and other JSON types.
		value = string(raw)
	}
	parsed, err := ParseKeepalive(value)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}
