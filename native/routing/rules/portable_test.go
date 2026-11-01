package rules

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

func TestPortableCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/portable-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string
		Invalid bool
		Config  json.RawMessage
		Probes  []struct {
			Domain, IP, Network string
			Port                uint16
			Action              Action
		}
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal(tc.Config, &cfg)
			if err == nil {
				cfg, err = cfg.Normalize()
			}
			if tc.Invalid {
				if err == nil {
					t.Fatal("accepted invalid portable policy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var restored Config
			if err = json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			for _, q := range tc.Probes {
				ip, _ := netip.ParseAddr(q.IP)
				if got := restored.MatchFlow(q.Domain, ip, q.Network, q.Port); got != q.Action {
					t.Fatalf("%+v: %s", q, got)
				}
			}
		})
	}
}

func TestPortValidation(t *testing.T) {
	if got, err := NormalizePorts("443, 80-81, 81-82,0080"); err != nil || got != "80-82,443" {
		t.Fatal(got, err)
	}
	for _, value := range []string{"0", "65536", "1-0", "1-2-3", "1,", ",1", "+1", "1.5", "１２", "-1", "80:90"} {
		if _, err := NormalizePorts(value); err == nil {
			t.Fatal("accepted", value)
		}
	}
}
