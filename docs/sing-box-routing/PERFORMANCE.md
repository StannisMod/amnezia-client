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
The subsequent CPU/block profile in
[run 41643494964](https://github.com/StannisMod/amnezia-client/actions/runs/41643494964)
showed heavy activity in gVisor's TCP processor sleep/park loop and race calls.
This led to the ARM64 race-only CAS defect described below.

The AWG socket-buffer A/B requested 7 MiB, matching the pinned upstream bind.
This did not materially improve the macOS race result. That runner reports
`kern.ipc.maxsockbuf=6291456`, below the request; the diagnostic ignores socket
buffer errors like upstream and does not read back the effective size. This
experiment therefore does **not** establish that socket-buffer tuning has no
effect. Production socket/protection settings were not changed.

## ARM64 race-only CAS fix

Both pinned gVisor modules contain the defective `pkg/sync/race_arm64.s`:
the replacement value overwrites the expected value in R1, while the store
reads R2. Park callbacks can consequently fail to enter their waiting state.
Google's upstream
[fix 1b2946c4](https://github.com/google/gvisor/commit/1b2946c4fa59c1a64643bce962140b5686062601)
loads the replacement into R2 instead. The file is built only with
`race && arm64`; ordinary product binaries do not compile it.

`prepare_race.py` verifies the pinned modules, copies them into a new private
temporary directory and applies exactly that one-instruction upstream fix to
each copy. Its temporary modfile redirects diagnostic builds to those copies.
The repository's production go.mod/go.sum and the shared module cache remain
unchanged. It refuses unexpected versions or assembly context. Remove this
workaround when both pinned dependencies contain the upstream correction.

`TestGVisorRaceCAS` checks successful replacement and rejection without
mutation in both modules, independently of network timing. The ARM64 performance
workflow requires this test to reproduce the original failure, then pass with
the private fixed dependencies before running the same measurements again.

The bulk correctness deadline is restored to its original **10 seconds**.
Authenticated traffic, exact bytes, dual-stack TCP/UDP, DNS assertions,
race detection and repetitions remain enabled.

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

For race instrumentation, first prepare the pinned upstream fix:

```sh
race_mod=$(python3 prepare_race.py --output "${TMPDIR:-/tmp}")
go test -mod=readonly -modfile="$race_mod" -tags with_gvisor,amnezia_race_dependency -race -count=3 ./...
```

Use the same `-modfile` for race benchmarks. The workflow
`.github/workflows/routing-performance.yml` runs these on Linux/macOS and also
performs the installed legacy/native Linux comparison. Reports contain no VPN
keys or profiles. These loopback fixtures do not exercise native mobile packet
flow, desktop route protection or external resolver latency; those require
separate device/network measurements.
