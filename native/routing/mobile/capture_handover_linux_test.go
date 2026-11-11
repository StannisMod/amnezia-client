//go:build linux && with_gvisor

package mobile

import (
	"context"
	"github.com/sagernet/sing-tun"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"golang.org/x/sys/unix"
)

func capturePair(t *testing.T) (int, net.Conn) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.SetNonblock(pair[1], true); err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(pair[1]), "handover-app")
	app, err := net.FileConn(file)
	file.Close()
	if err != nil {
		unix.Close(pair[0])
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	return pair[0], app
}

func TestCaptureDescriptorHandoverKeepsCoreAndFakeIP(t *testing.T) {
	for _, kind := range []string{"awg", "wireguard"} {
		t.Run(kind, func(t *testing.T) {
			fd, app := capturePair(t)
			releases := 0
			p, err := New(fd, Hooks{Protect: func(int) error { return nil }, Release: func() { releases++ }, Interfaces: func() ([]adapter.NetworkInterface, error) { return nil, nil }})
			if err != nil {
				unix.Close(fd)
				t.Fatal(err)
			}
			session, err := StartWithNetworkDNS(context.Background(), p, sampleConfig(t, kind))
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			capture := p.capture.(*packetDescriptor)
			core, endpoint := session.core, capture.endpoint
			expected := ""
			for generation := 0; generation < 25; generation++ {
				if generation > 0 {
					next, newApp := capturePair(t)
					old := capture.fd
					if err = capture.replaceDescriptor(next); err != nil {
						t.Fatal(err)
					}
					if _, err = unix.FcntlInt(uintptr(old), unix.F_GETFD, 0); err != unix.EBADF {
						t.Fatal("old capture survived handover", err)
					}
					app.Close()
					app = newApp
				}
				app.SetDeadline(time.Now().Add(time.Second))
				if _, err = app.Write(dnsPacket(t)); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, 4096)
				n, err := app.Read(reply)
				if err != nil {
					t.Fatal("handover lost packet reader", generation, err)
				}
				var answer dns.Msg
				if n < 28 {
					t.Fatal("truncated DNS reply")
				}
				if err = answer.Unpack(reply[28:n]); err != nil {
					t.Fatal(err)
				}
				if len(answer.Answer) != 1 {
					t.Fatal("missing managed DNS response")
				}
				address := answer.Answer[0].(*dns.A).A.String()
				if expected == "" {
					expected = address
				} else if address != expected {
					t.Fatal("handover changed FakeIP")
				}
				if session.core != core || p.capture != capture || capture.endpoint != endpoint || releases != 0 {
					t.Fatal("handover replaced core or packet endpoint")
				}
				if err = capture.CaptureError(); err != nil {
					t.Fatal("healthy reader reported stopped", err)
				}
			}
			current := capture.fd
			session.Close()
			if _, err = unix.FcntlInt(uintptr(current), unix.F_GETFD, 0); err != unix.EBADF {
				t.Fatal("current capture leaked", err)
			}
			if releases != 1 {
				t.Fatal("native owner release count", releases)
			}
			rejected, _ := capturePair(t)
			if err = capture.replaceDescriptor(rejected); err == nil {
				t.Fatal("closed capture accepted replacement")
			}
			if _, err = unix.FcntlInt(uintptr(rejected), unix.F_GETFD, 0); err != unix.EBADF {
				t.Fatal("failed replacement leaked incoming descriptor", err)
			}
		})
	}
}

func TestCaptureHandoverRacesCloseWithoutLeakingDescriptors(t *testing.T) {
	for i := 0; i < 25; i++ {
		fd, _ := capturePair(t)
		opened, err := openDescriptor(&tun.Options{FileDescriptor: fd, MTU: 1280})
		if err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		capture := opened.(*packetDescriptor)
		if err = capture.Start(); err != nil {
			t.Fatal(err)
		}
		next, _ := capturePair(t)
		var work sync.WaitGroup
		work.Add(2)
		go func() { defer work.Done(); capture.replaceDescriptor(next) }()
		go func() { defer work.Done(); capture.Close() }()
		done := make(chan struct{})
		go func() { work.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handover/close deadlock")
		}
		for _, owned := range []int{fd, next} {
			if _, err = unix.FcntlInt(uintptr(owned), unix.F_GETFD, 0); err != unix.EBADF {
				t.Fatal("owned descriptor leaked", owned, err)
			}
		}
		if capture.CaptureError() == nil {
			t.Fatal("closed capture reports healthy")
		}
	}
}
