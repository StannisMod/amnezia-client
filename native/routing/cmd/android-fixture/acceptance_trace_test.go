//go:build acceptance_trace && !stability_trace && !android && !ios

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestAcceptanceTraceIsBoundedAndExcludesPayload(t *testing.T) {
	trace := &acceptanceTrace{acceptanceTraceRows: &acceptanceTraceRows{}}
	packet := make([]byte, 64)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[20:], 12345)
	binary.BigEndian.PutUint16(packet[22:], 18082)
	copy(packet[28:], "private-payload-must-not-be-recorded")
	for i := 0; i < 300; i++ {
		trace.record("server_rx", packet)
	}
	if len(trace.rows) != 256 {
		t.Fatalf("unbounded or missing trace: %d", len(trace.rows))
	}
	row := trace.rows[255]
	if row.Protocol != 17 || row.Source != 12345 || row.Target != 18082 || row.Length != 64 {
		t.Fatalf("incorrect packet metadata: %+v", row)
	}
	encoded, err := json.Marshal(trace.rows)
	if err != nil || bytes.Contains(encoded, []byte("private-payload")) {
		t.Fatal("payload included in metadata", err)
	}
	trace.record("server_rx", nil)
	trace.record("server_rx", []byte{0x60})
	if len(trace.rows) != 256 {
		t.Fatal("malformed packets changed trace")
	}
}
