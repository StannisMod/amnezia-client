# Flow and DNS performance investigation

Measured on 2026-11-03. These are reproducible laboratory observations, not
Internet/VPS latency, device battery measurements or a cross-platform SLA.

## Ordinary builds versus race instrumentation

[Run 41642071270](https://github.com/StannisMod/amnezia-client/actions/runs/41642071270)
at `84f01c2` compares the same userspace loopback fixtures, payload and DNS paths
in ordinary and race-instrumented builds. macOS used a virtual Apple M1, ARM64,
three logical CPUs and Go 1.27.1. Bulk results are three timed 1 MiB transfers;
DNS results are 100 timed exchanges after warming the VPN handshake.

| macOS path | Ordinary | With `-race` |
| --- | ---: | ---: |
| Native TCP, 1 MiB | 0.47 ms | 3.27 ms |
| WireGuard flow transport, 1 MiB | 12.67 ms | 6.31 s |
| AWG flow transport, 1 MiB | 11.29 ms | 6.83 s |
| Native UDP DNS | 0.101 ms | 0.157 ms |
| AWG UDP DNS, real server exchange | 0.140 ms | 371.91 ms |
| DNS router over VPN, cache miss | 0.119 ms | 371.15 ms |
| DNS router, cached response | 0.003 ms | 0.036 ms |

The bulk benchmark verifies the complete payload and separately measures payload
receipt and EOF. EOF takes microseconds here: the slow race measurement is not
just waiting for the test server to close. Both WireGuard and AWG exhibit the
slowdown; the DNS router adds little to the already slow instrumented tunnel.
The ordinary macOS flow and DNS paths do not reproduce seconds of latency.
CPU/block profiles are collected in the performance workflow to investigate
the instrumented transport further; the precise cause is not established by
these timings alone.

The AWG socket-buffer A/B requested 7 MiB, matching the pinned upstream bind.
This did not materially improve the macOS race result. That runner reports
`kern.ipc.maxsockbuf=6291456`, below the request; the diagnostic ignores socket
buffer errors like upstream and does not read back the effective size. This
experiment therefore does **not** establish that socket-buffer tuning has no
effect. Production socket/protection settings were not changed.

The correctness test retains authenticated peer traffic, exact payload content,
dual-stack TCP/UDP and real DNS assertions. Its bulk deadline is 30 seconds
inside the existing one-minute session, accommodating the measured race cost
and scheduling variation. Race detection and repeated tests remain enabled.
Performance is measured separately in an ordinary build.

## Installed Linux legacy versus routed path

[Run 41640437982](https://github.com/StannisMod/amnezia-client/actions/runs/41640437982)
at `d7a1ea0` compares the installed legacy AWG 3.1.20260814 binary with the full
native routed TUN path. Both use the same observer, MTU 1280 and verified payload.
The report contains source/binary hashes and three 8 MiB measured samples after
the first transfer.

| Metric | Legacy AWG | Routed core |
| --- | ---: | ---: |
| Median throughput | 802.5 Mbit/s | 668.9 Mbit/s |
| Median CPU seconds per MiB | 0.015 | 0.02375 |
| Maximum observed RSS | 12,176 KiB | 47,492 KiB |

This run shows real overhead: about 17% lower throughput, 58% more CPU per MiB
and 3.9 times the observed RSS. Observed RSS is sampled, not a measured peak.
Absolute rates and ratios vary between shared runners and short runs; this is
not evidence of production performance parity or a universal 17% penalty.

## Reproduce

From `native/routing`, with the pinned Go toolchain and dependencies:

```sh
go test -mod=readonly -tags with_gvisor -run '^$' -bench '^BenchmarkTunnelBulk' -benchtime=3x -count=1 ./cmd/android-fixture
go test -mod=readonly -tags with_gvisor -run '^$' -bench '^BenchmarkTunnelDNS' -benchtime=100x -count=1 ./cmd/android-fixture
```

Repeat with `-race` to compare instrumentation. The workflow
`.github/workflows/routing-performance.yml` runs these on Linux/macOS and also
performs the installed legacy/native Linux comparison. Reports contain no VPN
keys or profiles. These loopback fixtures do not exercise native mobile packet
flow, desktop route protection or external resolver latency; those require
separate device/network measurements.
