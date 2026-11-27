package engine

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/awg"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

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

// Same private gVisor TCP stack, but with header-only observation at the peer's
// TUN boundary. The device uses upstream StdNetBind (also used by kernel-peer
// probes), so it does not depend on the app's fixed-endpoint bind filtering.
func stabilityUserspaceTracedPeer(t *testing.T, config awg.Config) (netip.AddrPort, net.Listener) {
	t.Helper()
	packet, flowStack, e := awg.NewFlowTUN(config.Address, 1280)
	if e != nil {
		t.Fatal(e)
	}
	directory := os.Getenv("AMNEZIA_STABILITY_TRACE")
	if directory == "" {
		t.Fatal("userspace trace requires AMNEZIA_STABILITY_TRACE")
	}
	if e = os.MkdirAll(directory, 0755); e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("%s-%d", strings.NewReplacer("/", "_", "[", "", "]", "", " ", "_").Replace(t.Name()), time.Now().UnixNano())
	if probeStack, ok := any(flowStack).(interface{ StabilityProbe(stabilityTCPProbeFunc) }); ok {
		file, err := os.Create(filepath.Join(directory, name+".probe.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		probeStack.StabilityProbe(func(state *stabilityTCPEndpointState) {
			s := state.Sender
			if state.ID.LocalPort != 18443 {
				return
			}
			row := map[string]any{"at": time.Now().Format(time.RFC3339Nano), "port": state.ID.RemotePort, "rto_s": s.RTO.Seconds(), "srtt_s": s.RTTState.SRTT.Seconds(), "rttvar_s": s.RTTState.RTTVar.Seconds(), "cwnd": s.SndCwnd, "outstanding": s.Outstanding, "wnd": s.SndWnd, "una": s.SndUna, "nxt": s.SndNxt, "fast_recovery": s.FastRecovery.Active, "recovery_last": s.FastRecovery.Last, "spurious": s.SpuriousRecovery}
			mu.Lock()
			json.NewEncoder(file).Encode(row)
			mu.Unlock()
		})
		t.Cleanup(func() { file.Close() })
	}
	output, e := os.Create(filepath.Join(directory, name+".packets.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	key := func(v string) string { b, _ := base64.StdEncoding.DecodeString(v); return hex.EncodeToString(b) }
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=0\n", key(config.PrivateKey))
	for k, v := range config.Parameters {
		ipc += k + "=" + v + "\n"
	}
	ipc += fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s\n", key(config.PublicKey), config.AllowedIPs[0])
	device, e := awg.NewConfiguredDevice(&stabilityTraceTUN{Device: packet, output: output}, conn.NewStdNetBind(), ipc)
	if e != nil {
		packet.Close()
		output.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { device.Close(); output.Close() })
	state, e := device.IpcGet()
	if e != nil {
		t.Fatal(e)
	}
	var port uint16
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			fmt.Sscanf(line, "listen_port=%d", &port)
		}
	}
	listener, e := flowStack.ListenTCPAddrPort(netip.AddrPortFrom(config.Address[0], 18443))
	if e != nil {
		t.Fatal(e)
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), listener
}
