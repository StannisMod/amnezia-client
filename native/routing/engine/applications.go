package engine

import (
	"errors"
	"regexp"
	"runtime"
	"strings"
)

// ApplicationScope selects which desktop processes reach the domain rules.
// Apps outside this scope use DIRECT. Failed/unknown ownership is rejected,
// rather than treating a possibly VPN-selected process as an excluded app.
// DNS is captured before this scope so shared system resolvers retain FakeIP
// identity. Mobile hosts continue to use their native per-application scope.
type ApplicationScope struct {
	Mode  string   `json:"mode"`
	Paths []string `json:"paths"`
}

func (s *ApplicationScope) compile() ([]any, error) {
	if s == nil {
		return nil, nil
	}
	if s.Mode != "include" && s.Mode != "exclude" {
		return nil, errors.New("invalid application scope mode")
	}
	if len(s.Paths) == 0 || len(s.Paths) > 256 {
		return nil, errors.New("application scope requires 1 to 256 executable paths")
	}
	patterns := make([]string, 0, len(s.Paths))
	for _, p := range s.Paths {
		if p == "" || strings.ContainsAny(p, "\x00\r\n") || len(p) > 32767 {
			return nil, errors.New("invalid application executable path")
		}
		pattern := "^" + regexp.QuoteMeta(p) + "$"
		if runtime.GOOS == "windows" {
			pattern = "(?i)" + pattern
		}
		patterns = append(patterns, pattern)
	}
	return []any{
		map[string]any{"process_path_regex": []string{".+"}, "invert": true, "action": "reject"},
		map[string]any{"process_path_regex": patterns, "invert": s.Mode == "include", "action": "route", "outbound": "direct"},
	}, nil
}
