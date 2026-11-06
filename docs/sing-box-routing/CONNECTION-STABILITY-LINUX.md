# Linux connection stability: independent TCP, real TUN and network events

2026-11-06. Investigation on `feature/connection-stability`, baseline `54b93e2`.
No recovery algorithm or production TCP option has been changed. The optional
`stability_trace` build tag exposes an observational gVisor probe; ordinary app
builds do not include it. This follows [the initial investigation](CONNECTION-STABILITY.md).

The subsequent [minimal TCP test and patch comparison](TCP-RECOVERY.md) selects a
tested experimental backport; it supersedes the earlier statement that no
candidate had yet been selected. Production dependency defaults remain unchanged.

## Findings

The large post-outage delay is not a fixed VPN reconnect timeout. TCP can return
to useful service in small bursts separated by long retransmission/recovery
intervals. This is measurable with the runtime and encrypted peer continuously
alive, no network callback, and the original WSS/TLS sessions intact.

The earlier **82.56 s** was the fixture's wait for **three additional complete
4096-byte download records AND three WSS exchanges**, measured after restoring
packet delivery. It was not a first-byte measurement and does not establish that
no TCP data arrived for 82 seconds. That run had no inner packet trace, so its
exact packet-by-packet timeline cannot be reconstructed. The fixture now reports
the first additional complete bulk record separately from the three-record goal.

The same class of slow recovery was traced in subsequent runs, including with
independent Linux TCP on the server. It is not sufficient to blame only the
initial two-gVisor fixture, or to change only the reconnect manager.

## Evidence for the sender recovery mechanism

An observational userspace-server run with `-race` reproduced a **50.28 s**
three-record delay after a 10-second blackhole. The runtime never closed.
Only TCP headers were captured at the peer's private TUN boundary:

- Packet delivery resumed at 10:59:52.55 UTC. Server data reached the client again
  around 10:59:55.17, and the next whole download record was observed by 10:59:55.77.
- The same bulk flow then made sparse progress. Another record was observed by
  11:00:18.77; the third-record goal completed at 11:00:42.83.
- Missing sequence ranges had already been transmitted before the outage. After
  ACKs arrived, retransmitting the next missing range could wait **12.36, 10.75,
  9.35, 8.13 and 7.06 seconds** in succession. The receive window stayed open.
- ACKs for retransmitted segments returned in about a millisecond; the other WSS
  stream continued while the download made little progress. This rules out a
  continuously dead UDP path or an application that had simply stopped producing
  these already-transmitted bytes.

A separate run with the pinned stack's own `AddTCPProbe` reproduced **56.00 s**
after a 10-second blackhole and recorded the internal state:

| State at recovery | Observed value |
| --- | --- |
| Maximum RTO observed on ACK processing | 14.20297 s |
| Example subsequent RTO | 12.42528 s, then 12.32811 s |
| Smoothed RTT / RTT variation at first large RTO | 1.57993 s / 3.15576 s |
| Congestion window | 5 packets |
| Estimated outstanding packets | 31, then 29 |
| Peer receive window | about 511 KiB, nonzero |
| Fast recovery | active |
| Spurious recovery flag in these samples | false |

This is a concrete sender recovery bottleneck: the RTT/RTO estimate becomes large,
and the recovery sender's estimate of outstanding packets exceeds its congestion
window. It cannot immediately resend all the missing bytes; progress waits for
subsequent recovery/timer opportunities even though ACKs for delivered packets
are now fast. The trace and probe agree about the source of the long pauses.

The relevant code is the private TCP stack's pinned `gvisor.dev/gvisor`
`1f7806d17489`, `pkg/tcpip/transport/tcp/snd.go`: `updateRTO`,
`retransmitTimerExpired`, `handleRcvdSegment`, `SetPipe`, `sendData`, and the SACK
recovery implementation. The measured `Outstanding > SndCwnd` state is directly
observed; identifying a minimal algorithmic fix or proving an RFC violation is
**not** an outcome of these experiments. No module cache was patched.

General RTO backoff and congestion response are required TCP behaviour, so
arbitrarily shortening timers is not a justified fix. See
[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html) and
[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html).

## Independent server and real Linux capture

The independent peer runs the pinned AWG/WG crypto device over a real Linux TUN in
a separate network namespace. Its HTTPS server listens on an actual kernel TCP
socket. The client reaches it over an isolated veth underlay. Both endpoints use
synthetic addresses only; no outside network or user server is involved.

For the real capture tests, the unchanged `cmd/amnezia-routing` desktop helper
owns `amnrouting0`, production capture nftables rules, policy routes, protected
outer UDP sockets, engine and cleanup. Application sockets are now Linux TCP
sockets, not `net.Pipe`. System DNS management is disabled with the existing
`--no-system-dns` fixture option; numeric target routing is tested, not DNS.

Each row below is a series of 1/3/10/30-second outages on the **same** two
connections. Values are additional seconds after restoring delivery until the
three-record/WSS goal, not first-byte latencies or performance guarantees.

| Client / independent Linux server | 1 s | 3 s | 10 s | 30 s | Outcome |
| --- | --- | --- | --- | --- | --- |
| Runtime, WG, inner IPv4, `-race` | 0.700 | 0.300 | 3.880 | 21.281 | same sessions |
| Desktop TUN helper, WG, inner IPv4, download | 0.661 | 0.281 | 3.161 | 22.701 | same sessions |
| Desktop TUN helper, AWG, inner IPv4, download | 0.681 | 0.261 | 2.980 | 22.700 | same sessions |
| Desktop TUN helper, WG, inner IPv6, download | 0.661 | 0.281 | 3.260 | 22.720 | same sessions |
| Desktop TUN helper, WG, inner IPv4, upload | 5.381 | 4.100 | 3.121 | 53.040 | same sessions |
| Desktop TUN helper, AWG, inner IPv4, upload | 5.381 | 4.301 | 26.902 | 69.802 | same sessions during outages; later FAIL |

The first five rows also pass the subsequent 10% loss / jitter phase. The AWG
upload run **fails** during that phase when the unchanged 200-second total HTTP
request budget expires (200.73 s fixture runtime including cleanup). WSS is still
exchanging messages, and there is no spontaneous helper reset. This is a native
Linux/TUN reproduction of an application timeout caused by insufficient useful
progress, with an independent kernel TCP server.

The AWG upload run's first additional confirmed records arrive after
4.480 / 3.420 / 3.020 / 45.881 seconds respectively; compare them to the three-record
goals above. In particular, the 10-second outage has a first record at about 3 s
and the three-record goal at about 27 s. This directly demonstrates why the two
metrics must not be conflated. Upload is a
streaming HTTPS POST: the Linux server checks each numbered 4096-byte record and
returns its sequence number. Only server-confirmed records count as progress.
Thus the 53-second case also concerns the client's own TCP sending path, not just
a gVisor sender artificially placed on the original test server.

In the upload header trace the client sends small data bursts separated by about
11.46, 9.95, 8.59 and 7.46 seconds while Linux ACKs received data. This is consistent
with the recovery bottleneck measured directly in the identical private gVisor
sender on the instrumented peer. The native helper itself has no TCP-probe hook;
its internal congestion state was not directly sampled.

All preservation assertions include unchanged application socket objects,
WS-ID=1, download/upload ID=1, exactly two server TCP accepts, and correct data.
After a deliberate helper/runtime stop, the old streams close; a new start yields
WS-ID=2. The helper PID and TUN lifetime remain continuous through the network
pauses; the test performs no reconnect at those points.

## Real NetworkManager events and production watcher

A separate disposable container runs real NetworkManager, D-Bus and udev with a
private virtual interface. It compiles the **unchanged**
`LinuxNetworkWatcherWorker` source; only its log sink is replaced. The worker has
normal thread affinity and subscribes to actual D-Bus `StateChanged` signals.
Raw D-Bus events and the worker's emitted signals are recorded independently.

Observed and asserted:

| Action | Observation |
| --- | --- |
| Packet blackhole, without link/carrier change | no production network/wakeup callback |
| Create/remove TUN and isolated policy route | no production network/wakeup callback |
| Replace gateway on the same interface, NM global state unchanged | no production network/wakeup callback |
| NM returns to global connected state 70 | `networkChanged` |
| `nmcli networking off`, state 10 | `wakeup` is emitted on **going offline** |
| Inject the same state 70 twice into the production slot | two `networkChanged` emissions |

There were three real state-70 events and one real state-10 event. Including the
two deliberately injected identical callbacks, the worker emitted five
`networkChanged` signals and one `wakeup`, exactly matching its implementation.
The actual duplicate injection is reported separately; the private NM did not
spontaneously produce an unexplained duplicate or TUN reconnect loop.

Consequences supported by the source: the watcher forwards global state events
without route-fingerprint deduplication, and the existing desktop reconnect path
can turn them into full backend teardown. `VpnConnection` also ignores callbacks
while its state is not Connected, so two watcher emissions alone do not prove
two actual backend resets. Conversely, a real path/gateway change
need not produce that particular global-state event. The full GUI/service
callback-to-teardown chain was not driven in this event fixture; its destructive
runtime/helper endpoint is tested separately above. This is not physical
Wi-Fi/suspend/device acceptance.

## Reproduction and artifacts

Build the lab image after the existing local full-build dependencies are prepared:

```sh
docker build --network host -t amnezia-connection-stability-lab \
  -f scripts/routing/stability/Dockerfile scripts/routing/stability
bash scripts/routing/run_linux_stability_lab.sh kernel /tmp/stability-kernel
STABILITY_RACE=1 bash scripts/routing/run_linux_stability_lab.sh kernel /tmp/stability-kernel-race
bash scripts/routing/run_linux_stability_lab.sh native /tmp/stability-wg
STABILITY_PROTOCOL=awg bash scripts/routing/run_linux_stability_lab.sh native /tmp/stability-awg
STABILITY_FAMILY=IPv6 bash scripts/routing/run_linux_stability_lab.sh native /tmp/stability-v6
STABILITY_UPLOAD=1 bash scripts/routing/run_linux_stability_lab.sh native /tmp/stability-upload
STABILITY_UPLOAD=1 STABILITY_PROTOCOL=awg bash scripts/routing/run_linux_stability_lab.sh native /tmp/stability-upload-awg
bash scripts/routing/run_linux_stability_lab.sh events /tmp/stability-events
STABILITY_RACE=1 STABILITY_PROBE=1 STABILITY_COUNT=2 \
  bash scripts/routing/run_linux_stability_lab.sh userspace /tmp/stability-probe
```

Runtime containers have `--network none`. Kernel/TUN/event modes use privileges
only within their disposable namespaces; no host namespace, D-Bus, Docker socket
or writable checkout is mounted. The shared module cache is read-only and the
build cache is separate. Build-time network access downloads tools only.

Files: `run.log`, header-only `*.tcp.txt` or `*.packets.jsonl`, kernel `*.ss.txt`,
optional `*.probe.jsonl`, netlink event log, environment versions. Event mode also
writes phase timestamps, watcher events and an asserted `report.json`.
`analyze_trace.py TRACE` summarizes data-burst and ACK-to-retransmission gaps in
a header trace, or RTO/congestion constraints in a probe trace;
its kernel-text parser is intentionally limited to inner IPv4. A missing initial
transmission at the remote capture point cannot be counted by that analyzer as a
confirmed retransmission: it may have been dropped before reaching the observer.

The iproute2 version in this image has no netem seed option. Native tests record
10% loss and 10 ms / 5 ms jitter per direction without claiming seeded replay.
Userspace packet-wrapper loss uses seed 604111; concurrent scheduling still affects
which packets receive each random draw. Outage durations are explicitly logged.

The original 200-second HTTP request budget is retained. A failing sequence that
hits it is reported as failure, not repaired by silently extending the timeout.
Diagnostic probes can perturb packet timing; the large effect is sensitive to
exact packet-loss timing and is not a stable 50/56/82-second constant.

Local evidence from this session is under `/tmp/amnezia-stability-kernel-race`,
`/tmp/amnezia-stability-userspace-race`, `/tmp/amnezia-stability-probe-repeat`,
`/tmp/amnezia-stability-native-wg-final`, `/tmp/amnezia-stability-native-awg-final`,
`/tmp/amnezia-stability-native-ipv6`, `/tmp/amnezia-stability-native-upload`,
`/tmp/amnezia-stability-native-upload-awg`, and
`/tmp/amnezia-stability-events-final`. These paths are transient; the source fixture
and commands above are the durable reproduction.

## Implications and limits

There are separate engineering concerns:

1. Preserve flow/TCP/device state when repairing outer reachability. The current
   full reconnect destroys it, as established by the initial tests.
2. Investigate and improve the private TCP sender's recovery behaviour with an
   independent Linux receiver. Preserving the object graph alone cannot prevent
   application timeouts when recovery makes insufficient useful progress.
3. Classify/coalesce actual network events. A callback is evidence to reconcile a
   path, not proof that the entire runtime must be destroyed.

The experiments do not choose a TCP patch, dependency upgrade, congestion
algorithm, timer setting or new recovery architecture. Neither the 82-second
metric nor one successful kernel-peer run alone justifies such a change.

Still outside this acceptance: full installed Qt service/GUI event wiring,
systemd-resolved/DNS policy changes, NAT rebinding, actual interface migration,
long offline, physical sleep/Wi-Fi, PMTU changes, kernel/legacy VPN modes, IPv6
underlay, Android/Apple/Windows, OpenVPN and Xray. The independent server shares
the host kernel with the container, but not gVisor TCP. No production VPN or
working-computer routes/firewall/DNS were used or changed.
