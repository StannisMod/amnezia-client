# TCP recovery: minimal reproducer and patch comparison

2026-11-06, `feature/connection-stability`, baseline `54b93e2`.
This completes the targeted experiment proposed after the
[Linux investigation](CONNECTION-STABILITY-LINUX.md).

**Integration update:** normal builds now use immutable fork revisions and
mandatory provenance/TCP checks. See [TCP-DEPENDENCY.md](TCP-DEPENDENCY.md). The
candidate comparison and its original deployment limits below are historical
evidence; the earlier statement that production defaults are unchanged is
superseded by that integration. No merge or release has been performed.

**Result:** a deterministic packet-level reproducer identifies RACK flight
accounting as the operative bottleneck. Of the compared backports, the RACK
accounting candidate passes the tested ACK/reordering/repair-loss cases and the
independent Linux/TUN scenarios. It is a **tested experimental candidate**, not a
new production dependency default: `go.mod`, `go.sum`, SDK build scripts and the
normal application recovery behaviour remain unchanged.

## Minimal test

`native/routing/awg/tcp_recovery_test.go`,
`TestTCPTimeoutRecoveryDrainsThroughACKs`, uses the exact pinned TCP protocol
implementation (`gvisor.dev/gvisor 1f7806d17489`), a channel link and a manual
clock. It needs no AWG device, TLS, Linux privilege or actual network outage.

The synthetic peer negotiates MSS 1240 and SACK, with or without TCP timestamps.
The MTU is 1280 and the receive window is 60000 bytes. The sender writes 39680
checked bytes. The peer drops the initial congestion window and tail probe, then
accepts the first RTO repair. Subsequent ACKs advance virtual time only 10 ms;
another RTO cannot silently make the test succeed.

Three delivery sequences are tested:

1. Ordered cumulative ACKs that cover part of the pre-timeout flight.
2. Deliver the third repair before the second, with a SACK for the held range.
3. Lose the second repair, deliver the third, and allow the real reordering timer
   to run without advancing to another RTO.

RACK-off controls cover the first two sequences. A single SACK need not trigger
classic SACK recovery of a lost repair, so that is not imposed on the control.
Together with timestamps on/off this gives **10 cases**. Sequence numbers are
handled relative to the sender's ISN; packet loss is by flight position, not
random timing. Out-of-order timestamps do not replace the last in-order echo.
Duplicate TCP repairs are acknowledged, not mistaken for application corruption.

The test requires complete, correct delivery after one RTO, checks a coarse bound
on newly emitted bursts (allowing a legal tail probe and a changed cwnd), and
rejects stalls or excess duplicate repair loops. Already emitted packets are not
incorrectly required to disappear when cwnd shrinks. This is a narrow synthetic
TCP receiver, not a replacement for independent Linux peer acceptance.

The ordinary unpatched module reproduces a stall after **2408 bytes without
TCP timestamps**, or **2400 bytes with timestamps**. In both cases its congestion
state becomes fast recovery, cwnd is five packets, and ACKs alone stop draining
the lost window. SACK-only controls complete. This removes the minutes-long,
scheduling-sensitive outage fixture from the causal demonstration.

The reproducer is opt-in with `AMNEZIA_TCP_RECOVERY_REPRO=1` because it intentionally
fails on the currently unchanged production dependency. The comparison wrapper
asserts that failure; it is not counted as a successful stock regression.

## Compared backports

Candidates are copied from the checksum-verified pinned module into private
folders. The module cache is mounted read-only. Every edit requires one exact
source context; the selected generated patch must match its checked-in review
artifact. No candidate is fetched or applied from an unpinned PR at test time.

| Candidate | Ordered ACKs | Reordered repairs | Lost repair | Selection |
| --- | --- | --- | --- | --- |
| stock | stalls with RACK | cannot provide required repairs | cannot provide required repairs | rejected |
| RTO-state guards, adapted from #16081 | passes | passes | waits for another timeout | rejected for this goal |
| RACK flight accounting, adapted from #15432 | passes | passes | passes | selected candidate |
| both changes | passes | passes | guard still blocks repair | rejected for this goal |

All ten cases pass for the selected candidate, including **100 repetitions with
`-race` (1000 case executions)**. Full Linux/amd64 Go regression with the candidate
and `with_gvisor,stability_trace -race` passes across `./...`.
The original module cache still passes `go mod verify` afterward.

The [selected backport](../../native/routing/patches/gvisor-rack-flight.patch)
changes three dependency files:

- Recompute `pipe` after RACK updates per-segment loss marks.
- Exclude a copy RACK marked lost from the in-flight count.
- Preserve `lost` and `acked` flags when a transmit queue entry is split.
- Advance `writeNext` past a fast repair so the ordinary send path does not emit
  that entry again immediately.

RTO minimum/maximum, congestion-control selection, congestion-window growth,
application timeouts, retry budgets and session lifetime are unchanged. The fix
works by accounting for loss, not by claiming every outstanding packet arrived
or by resetting TCP when the underlay returns.

SHA-256 of the review patch:
`f308f6c5558b6c29535408d7f37ac819598b4fcd4fb241366be12022e4356732`.

Upstream references are proposals, not completed independent review:
[#15432](https://github.com/google/gvisor/pull/15432),
[#16081](https://github.com/google/gvisor/pull/16081), and the maintainers'
[recovery review order](https://github.com/google/gvisor/issues/16670).
The comparison does not adopt #16495 or claim that combining all open proposals
would be safe. Copyright/license attribution is retained in copied sources and
[the patch directory](../../native/routing/patches/README.md).

## Independent Linux TCP and real TUN

The selected candidate is compiled into the real, otherwise unchanged desktop
helper with a temporary modfile. The server is independent Linux kernel TCP in a
separate network namespace. The same application sockets, WSS ID and stream ID
must survive the series of 1/3/10/30-second blackholes and subsequent 10% loss /
jitter phase; an automatic application reconnect cannot satisfy the test.

Passed: WG IPv4 download/upload, AWG IPv4 download/upload, WG inner IPv6 download,
and AWG inner IPv6 upload. All keep the original sessions and checked data. The
explicit final stop/start still destroys old sessions and creates a new WS ID.

Examples of observed post-restoration metrics (individual runs, not SLA or paired
statistical estimates):

| Case after 30-second blackhole | First additional confirmed bulk record | Three records + WSS exchanges |
| --- | --- | --- |
| Earlier stock AWG IPv4 upload | 45.881 s | 69.802 s |
| Candidate AWG IPv4 upload | 0.480 s | 21.261 s |
| Candidate WG IPv4 upload | 0.500 s | 21.260 s |

The earlier stock AWG sequence then expired its 200-second total request budget;
the candidate's measured AWG sequence, including loss/jitter, finishes in about
76 seconds. No request timeout was extended. The remaining ~21 seconds in the
joint goal includes the thin WSS flow's retransmission timing; it must not be
reported as a 21-second wait for the bulk stream's first byte.

Download from Linux can still wait about 22 seconds after a 30-second outage for
its own retransmission timing. The candidate does not alter the remote kernel's
TCP algorithm, so it does not promise instantaneous recovery of every flow.

Additional no-blackhole native checks pass for both stock and candidate:

- Slow path: 1 Mbit/s, 100 ms delay with 50 ms jitter per direction, qdisc limit
  256 packets, at least eight seconds impaired and ten completed exchanges.
- Reordering without configured loss: 40 ms delay with 10 ms jitter, 25% reorder
  with 50% correlation per direction, qdisc limit 256, eight-second observation.

The reordering samples deliver 398/399 records and 77/79 WSS exchanges respectively
(stock/candidate). Slow-path observations show continued verified transfer near
the configured rate for both. These are functional checks, not a throughput or
congestion-fairness benchmark; native netem random draws cannot be seeded with
this image's iproute2. They do not prove parity under all path conditions.

## Reproduce

Prepare the existing local-build toolchain/cache and the lab image described in
[the Linux report](CONNECTION-STABILITY-LINUX.md). Use a fresh output directory.

```sh
# Expected stock failure, rejected alternatives, selected candidate + race checks.
bash scripts/routing/run_tcp_recovery_comparison.sh /tmp/tcp-comparison-new

# Patched backend in isolated native TUN fixtures.
STABILITY_TCP_CANDIDATE=pipe bash scripts/routing/run_linux_stability_lab.sh native /tmp/tcp-wg-new
STABILITY_TCP_CANDIDATE=pipe STABILITY_UPLOAD=1 \
  bash scripts/routing/run_linux_stability_lab.sh native /tmp/tcp-wg-upload-new
STABILITY_TCP_CANDIDATE=pipe STABILITY_PROTOCOL=awg STABILITY_UPLOAD=1 \
  bash scripts/routing/run_linux_stability_lab.sh native /tmp/tcp-awg-upload-new

# Healthy but reordered or slow paths, without preceding blackholes.
STABILITY_TCP_CANDIDATE=pipe STABILITY_NO_OUTAGES=1 STABILITY_PROFILE=reorder \
  STABILITY_IMPAIRMENT_SECONDS=8 bash scripts/routing/run_linux_stability_lab.sh native /tmp/tcp-reorder-new
# Substitute STABILITY_PROFILE=slow or STABILITY_TCP_CANDIDATE=stock to compare.
```

The wrapper sets `GOFLAGS=-modfile=...` only inside the disposable test container.
It does not make the patch a normal application build default. Source checkout
and module cache are read-only during comparison; no user VPS, desktop routes,
firewall, DNS or VPN session are used.

Transient evidence: `/tmp/amnezia-tcp-comparison-final`,
`/tmp/amnezia-tcp-pipe-{wg,awg}-{download,upload}`,
`/tmp/amnezia-tcp-pipe-wg-ipv6`, `/tmp/amnezia-tcp-pipe-awg-ipv6-upload`, and
`/tmp/amnezia-tcp-{stock,pipe}-{slow,reorder}`. Source and commands are durable;
these local artifact directories are not committed.

## Limits before a production dependency change

This is evidence for the chosen candidate on Linux/amd64 with the production
FlowStack's non-GSO path. It is not a completed SDK/release gate or independent
TCP-specialist review. Do not promote the open upstream PR to an already-reviewed
fix. Its broader TCP accounting neighbours, including
[SACK credit](https://github.com/google/gvisor/pull/15634), still need consideration.

In particular this does not exhaust GSO packet ownership, partial-MSS cumulative
ACK/SACK boundaries, PMTU reductions, arbitrary packet overlap, congestion
fairness, prolonged WAN loss or every reordering pattern. Other OS SDKs and ARM64
race still need their prescribed checks; ARM64 race must use the existing private
CAS correction rather than patching the shared cache. Ordinary production builds
continue to use the original dependency until an explicit integration change is
made and validated.

The selected TCP candidate also does not change the outer recovery manager:
full runtime destruction still loses old flows. That is a separate architectural
problem from the sender stall now reproduced and bounded by a minimal test.
