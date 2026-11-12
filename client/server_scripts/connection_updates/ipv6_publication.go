package main

import (
	"bytes"
	"encoding/json"
	"errors"
)

type ipv6PublicationReceipt struct {
	Operation     string            `json:"operation"`
	ExpectedState string            `json:"expectedState"`
	RequestHash   string            `json:"requestHash"`
	Assignments   map[string]string `json:"assignments"`
	Revisions     map[string]uint64 `json:"revisions"`
}

func ipv6PublicationHash(container, expected string, assignments map[string]string) string {
	raw, _ := json.Marshal(struct {
		Container   string            `json:"container"`
		Expected    string            `json:"expectedState"`
		Assignments map[string]string `json:"assignments"`
	}{container, expected, assignments})
	return configHash(raw)
}
func validateIPv6Publications(s *state) error {
	for container, receipt := range s.IPv6Publications {
		if !containerOK(container) || !configOperationOK(receipt.Operation) || !configOperationOK(receipt.ExpectedState) || receipt.Assignments == nil || receipt.Revisions == nil || receipt.RequestHash != ipv6PublicationHash(container, receipt.ExpectedState, receipt.Assignments) {
			return errors.New("invalid IPv6 publication receipt")
		}
		if err := clientIPv6AssignmentsOK(receipt.Assignments); err != nil {
			return err
		}
		for id, revision := range receipt.Revisions {
			if !idPattern.MatchString(id) || revision == 0 {
				return errors.New("invalid IPv6 publication revision")
			}
		}
	}
	return nil
}
func currentIPv6Publication(s *state, container string, receipt ipv6PublicationReceipt) bool {
	count := 0
	for id, record := range s.Records {
		if record.Container != container || record.Revoked {
			continue
		}
		wanted, selected := receipt.Assignments[record.ClientPublicKey]
		if !selected {
			continue
		}
		count++
		if receipt.Revisions[id] != record.Revision || record.ClientIPv6 == nil || *record.ClientIPv6 != wanted {
			return false
		}
	}
	return count == len(receipt.Revisions)
}
func publishClientIPv6(s *state, req request) (bool, error) {
	if !containerOK(req.Container) || !configOperationOK(req.Operation) || !configOperationOK(req.ExpectedState) || req.ClientIPv6 == nil {
		return false, errors.New("invalid conditional IPv6 publication")
	}
	// This command may change only the key-bound IPv6 extension and its revision.
	if publicationHasSettings(req.Settings) || req.PathMTUProbe != "" || req.ClientPublicKey != "" || req.ClientPublicKeys != nil || req.Host != "" {
		return false, errors.New("unrelated settings in IPv6 publication")
	}
	if err := clientIPv6AssignmentsOK(req.ClientIPv6); err != nil {
		return false, err
	}
	digest := ipv6PublicationHash(req.Container, req.ExpectedState, req.ClientIPv6)
	if receipt, known := s.IPv6Publications[req.Container]; known && receipt.Operation == req.Operation {
		if receipt.RequestHash != digest {
			return false, errors.New("IPv6 operation reused for different request")
		}
		if !currentIPv6Publication(s, req.Container, receipt) {
			return false, errors.New("IPv6 publication was superseded")
		}
		return true, nil
	}
	if req.ExpectedState != stateTag(s) {
		return false, errors.New("subscription state changed")
	}
	receipt := ipv6PublicationReceipt{Operation: req.Operation, ExpectedState: req.ExpectedState, RequestHash: digest, Assignments: map[string]string{}, Revisions: map[string]uint64{}}
	for key, address := range req.ClientIPv6 {
		receipt.Assignments[key] = address
	}
	for id, record := range s.Records {
		if record.Container != req.Container || record.Revoked {
			continue
		}
		address, selected := req.ClientIPv6[record.ClientPublicKey]
		if !selected {
			continue
		}
		if record.Revision == ^uint64(0) {
			return false, errors.New("revision exhausted")
		}
		record.Revision++
		record.ClientIPv6 = &address
		s.Records[id] = record
		receipt.Revisions[id] = record.Revision
	}
	if s.IPv6Publications == nil {
		s.IPv6Publications = map[string]ipv6PublicationReceipt{}
	}
	s.IPv6Publications[req.Container] = receipt
	return false, nil
}
func ipv6PublicationStatus(s *state, req request) (map[string]any, error) {
	if !containerOK(req.Container) || !configOperationOK(req.Operation) {
		return nil, errors.New("invalid IPv6 publication status request")
	}
	if req.ClientIPv6 != nil || req.ExpectedState != "" || publicationHasSettings(req.Settings) || req.PathMTUProbe != "" || req.ClientPublicKey != "" || req.ClientPublicKeys != nil || req.Host != "" {
		return nil, errors.New("unexpected IPv6 status fields")
	}
	result := info(s)
	receipt, known := s.IPv6Publications[req.Container]
	known = known && receipt.Operation == req.Operation
	result["known"] = known
	result["current"] = known && currentIPv6Publication(s, req.Container, receipt)
	if known {
		result["operation"] = receipt.Operation
	}
	return result, nil
}

func publicationHasSettings(raw json.RawMessage) bool {
	value := bytes.TrimSpace(raw)
	return len(value) != 0 && !bytes.Equal(value, []byte("null"))
}
