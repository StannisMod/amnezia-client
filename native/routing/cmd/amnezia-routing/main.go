//go:build (linux && !android) || windows

// amnezia-routing is a private child of the privileged desktop service.
// Credentials arrive on stdin, never in command lines or configuration files.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/StannisMod/amnezia-client/native/routing/desktop"
)

func main() {
	noDNS := flag.Bool("no-system-dns", false, "isolated namespace test only: caller supplies resolver configuration")
	recoverOnly := flag.Bool("recover", false, "explicit recovery of recognized fail-closed state after a child crash")
	cacheDir := flag.String("cache-dir", desktop.DefaultCacheDir(), "private service cache directory")
	flag.Parse()
	lock, err := desktop.PreparePrivateCache(*cacheDir)
	if err != nil {
		os.Exit(1)
	}
	defer lock.Close()
	if *recoverOnly {
		if err := desktop.Recover(); err != nil {
			fmt.Fprintln(os.Stderr, "routing recovery failed:", err)
			os.Exit(1)
		}
		return
	}
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 4096), 4<<20)
	var output sync.Mutex
	write := func(value any) { output.Lock(); defer output.Unlock(); json.NewEncoder(os.Stdout).Encode(value) }
	fail := func(message string) { write(map[string]any{"type": "error", "message": message}) }
	if !input.Scan() {
		fail("missing routing profile")
		return
	}
	config, err := desktop.ProfileSession(input.Bytes())
	if err != nil {
		fail(err.Error())
		return
	}
	if err := desktop.PrepareResolver(&config); err != nil {
		fail(err.Error())
		return
	}
	rawConfig, _ := json.Marshal(config)
	var sessionConfig map[string]any
	json.Unmarshal(rawConfig, &sessionConfig)
	sessionConfig["cache_path"] = filepath.Join(*cacheDir, "fakeip-v1.db")
	rawConfig, _ = json.Marshal(sessionConfig)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	session, err := desktop.Start(ctx, rawConfig, !*noDNS)
	if err != nil {
		fail(err.Error())
		return
	}
	defer session.Close()
	write(map[string]any{"type": "ready", "interface": desktop.InterfaceName, "capture_id": session.CaptureID()})
	commands := make(chan string)
	go func() {
		defer close(commands)
		for input.Scan() {
			commands <- input.Text()
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	connected := false
	for {
		select {
		case <-ctx.Done():
			session.Abort()
			return
		case command, ok := <-commands:
			if !ok {
				session.Abort()
				return
			}
			if command == "stop" {
				return
			}
		case <-ticker.C:
			stats, err := session.Stats()
			if err != nil {
				fail("routing statistics unavailable")
				session.Abort()
				return
			}
			if !connected && stats.LastHandshake > 0 {
				connected = true
				write(map[string]any{"type": "connected", "pubkey": config.AWG.PublicKey})
			}
			write(map[string]any{"type": "status", "connected": connected, "rxBytes": stats.RXBytes, "txBytes": stats.TXBytes, "deviceIpv4Address": "172.19.0.1", "serverIpv4Gateway": "172.19.0.2"})
		}
	}
}
