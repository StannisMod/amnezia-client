//go:build stability_trace && !android && !ios

package main

import (
	"encoding/binary"
"context"
"net/http"
"strconv"
	"encoding/hex"
	"encoding/json"
	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"os"
	"sync"
	"time"
)

func init() {
	wrapSenderTrace = func(t tun.Device, s *awg.FlowStack) tun.Device {
		previous:=labControl
        labControl=func(m *http.ServeMux){
          if previous!=nil{previous(m)}
          m.HandleFunc("/lab-echo",func(w http.ResponseWriter,r *http.Request){
            size,_:=strconv.Atoi(r.URL.Query().Get("size"))
            ctx,cancel:=context.WithTimeout(r.Context(),time.Second);defer cancel()
            json.NewEncoder(w).Encode(map[string]any{"size":size,"echo":s.LabEcho(ctx,size)})
          })
        }
        s.StabilityProbe(func(p *stack.TCPEndpointState) {
			if p.ID.LocalPort == 18081 {
				json.NewEncoder(os.Stdout).Encode(map[string]any{"at": time.Now(), "port": p.ID.RemotePort, "rto_ms": p.Sender.RTO.Milliseconds(), "una": p.Sender.SndUna})
			}
		})
		return &stabilityTraceTUN{Device: t, output: os.Stdout}
	}
}

type stabilityTraceTUN struct {
	tun.Device
	mu     sync.Mutex
	output *os.File
}

func (s *stabilityTraceTUN) record(direction string, b []byte) {
	if len(b) < 20 {
		return
	}
	offset := 0
	end := len(b)
	switch b[0] >> 4 {
	case 4:
		if b[9] != 6 {
			return
		}
		offset = int(b[0]&15) * 4
		end = int(binary.BigEndian.Uint16(b[2:4]))
	case 6:
		if len(b) < 40 || b[6] != 6 {
			return
		}
		offset = 40
		end = 40 + int(binary.BigEndian.Uint16(b[4:6]))
	default:
		return
	}
	if end > len(b) || offset < 20 || end < offset+20 {
		return
	}
	tcp := b[offset:end]
	hlen := int(tcp[12]>>4) * 4
	if hlen < 20 || hlen > len(tcp) {
		return
	}
	row := map[string]any{"at": time.Now().Format(time.RFC3339Nano), "direction": direction, "sport": binary.BigEndian.Uint16(tcp[:2]), "dport": binary.BigEndian.Uint16(tcp[2:4]), "seq": binary.BigEndian.Uint32(tcp[4:8]), "ack": binary.BigEndian.Uint32(tcp[8:12]), "flags": tcp[13], "window": binary.BigEndian.Uint16(tcp[14:16]), "length": len(tcp) - hlen, "options": hex.EncodeToString(tcp[20:hlen])}
	s.mu.Lock()
	json.NewEncoder(s.output).Encode(row)
	s.mu.Unlock()
}
func (s *stabilityTraceTUN) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	n, e := s.Device.Read(buf, sizes, offset)
	for i := 0; i < n; i++ {
		s.record("server_tx", buf[i][offset:offset+sizes[i]])
	}
	return n, e
}
func (s *stabilityTraceTUN) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		s.record("server_rx", b[offset:])
	}
	return s.Device.Write(buf, offset)
}
