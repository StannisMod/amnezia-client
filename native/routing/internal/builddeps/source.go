package builddeps

import (
	_ "embed"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime/debug"
)

// Lock is shared by build verification, runtime provenance and package notices.
//
//go:embed lock.json
var Lock []byte

type Pin struct {
	UpstreamVersion string `json:"upstream_version"`
	UpstreamCommit  string `json:"upstream_commit"`
	Module          string `json:"module"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	Sum             string `json:"sum"`
}
type Pins struct {
	SchemaVersion int            `json:"schema_version"`
	FixID         string         `json:"fix_id"`
	Profiles      map[string]Pin `json:"profiles"`
}
type Info struct {
	Mode            string `json:"mode"`
	FixID           string `json:"fix_id"`
	Profile         string `json:"profile"`
	UpstreamVersion string `json:"upstream_version"`
	UpstreamCommit  string `json:"upstream_commit"`
	Module          string `json:"module"`
	Version         string `json:"version"`
	Sum             string `json:"sum"`
	Commit          string `json:"commit"`
	GoVersion       string `json:"go_version"`
}

// Source contains only build identifiers, never VPN profiles, keys or application destinations.
func Source() Info {
	fix, base, commit, mode := linkedSource()
	result := Info{Mode: mode, FixID: fix, UpstreamVersion: base, UpstreamCommit: commit}
	if mode != "fixed" {
		return result
	}
	var pins Pins
	if json.Unmarshal(Lock, &pins) != nil || pins.SchemaVersion != 1 || pins.FixID != fix {
		result.Mode = "invalid"
		return result
	}
	var expected Pin
	for profile, pin := range pins.Profiles {
		if pin.UpstreamVersion == base && pin.UpstreamCommit == commit {
			result.Profile = profile
			expected = pin
			break
		}
	}
	if result.Profile == "" {
		result.Mode = "invalid"
		return result
	}
	result.Commit = expected.Commit
	if info, ok := debug.ReadBuildInfo(); ok {
		result.GoVersion = info.GoVersion

		expectedProfile := profileForMain(info.Main.Path)
		if expectedProfile != "" && expectedProfile != result.Profile {
			result.Mode = "invalid"
			return result
		}
		for _, module := range info.Deps {
			if module.Path != "gvisor.dev/gvisor" {
				continue
			}
			if module.Replace == nil {
				result.Mode = "invalid"
				return result
			}
			replacement := module.Replace
			// Avoid disclosing local build paths from an unsupported local replace.
			if module.Version != expected.UpstreamVersion {
				result.Mode = "invalid"
				return result
			}
			if replacement.Path != expected.Module {
				if allowRaceDependency() && filepath.IsAbs(replacement.Path) {
					result.Mode = "race-diagnostic"
					return result
				}
				result.Mode = "invalid"
				return result
			}
			result.Module, result.Version, result.Sum = replacement.Path, replacement.Version, replacement.Sum
			if module.Version != expected.UpstreamVersion || replacement.Version != expected.Version || replacement.Sum != expected.Sum {
				result.Mode = "invalid"
			}
			return result
		}
	}
	// Go test binaries may omit the dependency build-info payload. Production
	// artifacts are independently required to expose the full locked identity.
	return result
}
func Validate() error {
	mode := Source().Mode
	if mode == "fixed" || (mode == "reproduction" && allowReproduction()) || (mode == "race-diagnostic" && allowRaceDependency()) {
		return nil
	}
	return errors.New("routing TCP dependency provenance is not verified")
}

func profileForMain(path string) string {
	return map[string]string{
		"github.com/StannisMod/amnezia-client/native/routing": routingComponentProfile,
		"github.com/amnezia-vpn/amneziawg-android":            "desktop_android",
		"github.com/amnezia-vpn/amneziawg-apple":              "apple",
	}[path]
}
