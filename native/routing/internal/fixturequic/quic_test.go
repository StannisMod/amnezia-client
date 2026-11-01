package fixturequic

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSVerifiedSegmentedProbeAndWrongCA(t *testing.T) {
	cert, err := Certificate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.der")
	if err = os.WriteFile(path, cert.Certificate[0], 0600); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"VPN", "DIRECT"} {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server, err := Serve(pc, cert, label)
		if err != nil {
			pc.Close()
			t.Fatal(err)
		}
		got, err := Probe(pc.LocalAddr().String(), path)
		if err != nil || got != label {
			server.Close()
			pc.Close()
			t.Fatal(label, got, err)
		}
		other, err := Certificate()
		if err != nil {
			t.Fatal(err)
		}
		wrong := filepath.Join(t.TempDir(), "wrong.der")
		os.WriteFile(wrong, other.Certificate[0], 0600)
		if _, err = Probe(pc.LocalAddr().String(), wrong); err == nil {
			t.Fatal("QUIC accepted a different fixture CA")
		}
		server.Close()
		pc.Close()
	}
}
