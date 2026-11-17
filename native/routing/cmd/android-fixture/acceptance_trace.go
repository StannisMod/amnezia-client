//go:build acceptance_trace && !stability_trace && !android && !ios

package main

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Retain only bounded TCP/UDP header metadata, never packet payload or keys.
type acceptancePacket struct {
	At        time.Time `json:"at"`
	Direction string    `json:"direction"`
	Protocol  byte      `json:"protocol"`
	Source    uint16    `json:"source_port"`
	Target    uint16    `json:"target_port"`
	Flags     byte      `json:"tcp_flags,omitempty"`
	Length    int       `json:"length"`
}

type acceptanceTrace struct {
	tun.Device
	*acceptanceTraceRows
}

type acceptanceTraceRows struct {
	mu   sync.Mutex
	rows []acceptancePacket
}

func (t *acceptanceTrace) record(direction string, packet []byte) {
	if len(packet) < 20 {
		return
	}
	var offset int
	var protocol byte
	switch packet[0] >> 4 {
	case 4:
		offset, protocol = int(packet[0]&15)*4, packet[9]
		if offset < 20 {
			return
		}
	case 6:
		if len(packet) < 40 {
			return
		}
		offset, protocol = 40, packet[6]
	default:
		return
	}
	if (protocol != 6 && protocol != 17) || len(packet) < offset+8 {
		return
	}
	header := packet[offset:]
	row := acceptancePacket{At: time.Now(), Direction: direction, Protocol: protocol,
		Source: binary.BigEndian.Uint16(header), Target: binary.BigEndian.Uint16(header[2:]),
		Length: len(packet)}
	if protocol == 6 {
		if len(header) < 20 {
			return
		}
		row.Flags = header[13]
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.rows) == 256 {
		copy(t.rows, t.rows[1:])
		t.rows = t.rows[:255]
	}
	t.rows = append(t.rows, row)
}

func (t *acceptanceTrace) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(buf, sizes, offset)
	for i := 0; i < n; i++ {
		t.record("server_tx", buf[i][offset:offset+sizes[i]])
	}
	return n, err
}

func (t *acceptanceTrace) Write(buf [][]byte, offset int) (int, error) {
	for _, packet := range buf {
		t.record("server_rx", packet[offset:])
	}
	return t.Device.Write(buf, offset)
}

func init() {
	buffer := &acceptanceTraceRows{}
	wrapSenderTrace = func(device tun.Device, _ *awg.FlowStack) tun.Device {
		return &acceptanceTrace{Device: device, acceptanceTraceRows: buffer}
	}
	previous := labControl
	labControl = func(mux *http.ServeMux) {
		if previous != nil {
			previous(mux)
		}
		mux.HandleFunc("/acceptance-packets", func(w http.ResponseWriter, _ *http.Request) {
			buffer.mu.Lock()
			rows := append([]acceptancePacket(nil), buffer.rows...)
			buffer.mu.Unlock()
			json.NewEncoder(w).Encode(rows)
		})
	}
}
