# Connection stability investigation

2026-11-06. Baseline: `54b93e2` (`dev`, including DNS PR #14).
Branch: `feature/connection-stability`. This is an investigation and proposed
architecture, not an implemented recovery change or completed platform acceptance.

For the subsequent independent Linux TCP, real desktop TUN and NetworkManager
results, see [Linux follow-up](CONNECTION-STABILITY-LINUX.md). The limitations
below describe the initial fixture; the follow-up supersedes the tested subset.

## Reproduction

The new opt-in `engine/TestConnectionStabilityReproduction` uses production
`StartRuntime`, `Router.RouteConnectionEx`, outbound, encrypted AWG/WG device and
private TCP stack. Application sockets enter through `net.Pipe`, replacing only
the OS capture side. The peer is a separate device with its own private stack;
both outer sockets are real IPv4 UDP on container loopback. IPv4/IPv6 below refer
to **inner traffic**, not IPv6 underlay.

Two concurrent TLS connections carry a WSS request/response stream (numbered
messages, 25 ms pacing) and an HTTP/1.1 download (4096-byte numbered and checked
records, 20 ms pacing). The server assigns WS and download IDs and counts TCP
accepts. Application reconnection is disabled. Reusing the same client objects,
server IDs, sequence and checked data, with exactly two server accepts, is
required before the deliberate reset.

The AWG profile uses Jc=3, Jmin/Jmax=40/80, S1..S4=16/24/8/8,
H1..H4=1001/1002/1003/1004; standard WG omits extensions. A PacketConn wrapper
silently discards encrypted UDP datagrams in both directions during blackholes.
It leaves socket identities and addresses intact and sends no network-change
callback. A separate phase applies 10% independent packet loss per direction
and 5..20 ms delay to surviving packets. Seed=604111; scheduling changes which
packet consumes each RNG value, so the seed does not guarantee an identical trace.
There is no reordering simulation or queue of delayed packets.

Each isolated matrix case has a fresh pair of application connections. The
fixture lifetime and WSS socket deadline are 240 seconds; the HTTP client timeout
is 200 seconds, and each progress check allows 100 seconds. These are fixture
budgets to observe recovery, not proposed application or production timer changes.
Progress time measures the return of at least three messages and download records,
not exact first-packet latency.

Observed isolated matrix, one ordinary Linux/amd64 run:

| Blackhole | AWG inner IPv4/IPv6 | WG inner IPv4/IPv6 | Additional time until progress |
| --- | --- | --- | --- |
| 1 s | same connections | same connections | 5.66..5.68 s |
| 3 s | same connections | same connections | 2.46..24.34 s |
| 10 s | same connections | same connections | 2.88..2.90 s |
| 30 s | same connections | same connections | 21.30 s |

All 16 cases also survived the subsequent loss/delay phase. These are observations,
not speed guarantees: some loss/delay phases themselves took much longer to return
progress. The extra delays require packet/retransmission/queue tracing before
assigning a cause or changing timers.

In every case, explicitly closing the runtime then broke both existing streams
(EOF/closed pipe/unexpected EOF), observed within 1..22 ms. Starting an identical
runtime restored availability but created WS-ID=2 instead of WS-ID=1. This proves
the destructive effect of the operation, not that the user's real incident was
necessarily triggered by that operation.

`awg/TestBindUpdatePreservesEstablishedTCP` separately tests the pinned device's
`BindUpdate()` primitive: one TCP socket and one server accept survive three real
UDP socket close/open operations for both AWG and standard WG and both inner
families. Four socket factory calls are required. This reuses the same local UDP
port and peer; it does not establish NAT rebinding/interface-change support.
Existing interoperability tests against independent upstream wireguard-go pass.

The package regression tests for `awg`, `wireguard`, and `engine` passed with
`-race` on Linux/amd64. The normal regression run skips the opt-in long reproduction.

The corrected successive-outage probe was also run with `-race`, restricted to
standard WG / inner IPv4. The same WSS and download survived 1, 3 and 10 seconds
of blackhole in succession. After the 10-second pause, joint progress returned
only after **82.56 seconds**; the WSS count increased substantially while the bulk
stream lagged. During the subsequent 30-second pause/recovery, the download hit
its configured **200-second total HTTP request timeout**. This sequence therefore
**FAILS** the preservation test; the final failure is an application timeout, not
`Runtime.Close()` or the endpoint watchdog. This does not mean a 200-second outage:
the request budget includes all earlier pauses and recovery delays. No data-race
report was emitted. The fixture puts gVisor on both sides, so determining whether
the delayed download is caused by sender/receiver retransmission, SACK, windows,
queues or an implementation defect requires packet-level tracing and a peer with
an independent TCP stack. Increasing the fixture timeout is not a product fix.

## How to run

With the dependencies and toolchain prepared by `scripts/local-tests/build-full.sh`:

```sh
bash scripts/routing/run_connection_stability_reproduction.sh matrix
bash scripts/routing/run_connection_stability_reproduction.sh sequence
```

The wrapper mounts the shared dependency volume read-only, keeps a separate Go
build cache, disables external container networking, and grants no privileged
capabilities. It runs AWG/WG tests with the race detector followed by the long
runtime experiment. `sequence` keeps the same connections through 1/3/10/30-second
blackholes in succession, exposing accumulated recovery delays. On a host with
Go 1.27.1 and the module dependencies already installed, equivalent commands are:

```sh
cd native/routing
go test -mod=readonly -tags with_gvisor -race -count=1 ./awg ./wireguard ./engine
AMNEZIA_STABILITY_REPRO=1 go test -mod=readonly -tags with_gvisor -parallel 16 \
  -run TestConnectionStabilityReproduction -count=1 -timeout 6m -v ./engine
# Add AMNEZIA_STABILITY_SEQUENCE=1 for successive outages on the same streams.
```

ARM64 race runs must follow `TESTING.md` and `prepare_race.py`; never patch the
shared module cache. No host routes/firewall/DNS or production VPS are involved.

## Where state is lost

The source-level desktop reconnect path is:

1. `VpnConnection::reconnectToVpn()` receives network/wakeup notifications.
2. `WireguardProtocol::reconnect()` restarts the endpoint session for a domain,
   or calls stop/start directly for a numeric endpoint.
3. `VpnEndpointSession::start()`/`recover()` enter real backend teardown.
4. `DesktopRoutingProcess::stop()` tells the helper to stop; its `start()` also
   begins by stopping the existing helper.
5. Desktop/mobile session closure reaches `engine.Runtime.Close()`, which cancels
   the runtime and closes sing-box. Outbound scope cleanup closes `Transport`.
6. `Transport.Close()` closes the device, which closes the private TUN/FlowStack;
   `FlowStack.Close()` removes the NIC and closes the TCP stack. Both the router's
   application flow ownership and the VPN-side TCP state are lost.

Domain watchdog recovery uses the same teardown. Its default stale budget is
240 seconds and requires sending without inbound/handshake progress; the short
blackhole tests do not exercise it. Numeric endpoints have a different path and
must receive the same eventual recovery policy.

There is another source-level trigger: a changed underlying DNS fingerprint makes
`resolvedLink.reconcile()` return a reconnect-required error. That propagates
through session statistics to helper abort and runtime closure. No DNS-change
experiment has yet been run here.

Linux `NMStateChanged()` emits `wakeup` on ASLEEP/DISABLED and `networkChanged` on
CONNECTED_GLOBAL. The payload does not establish whether the actual endpoint
route changed. Actual NetworkManager event sequences and duplicate/self-generated
events remain to be reproduced; these findings do not prove a live callback loop.

## Proposed architecture

A session owns long-lived capture, router flows, FakeIP identities, VPN-side TCP
stack, device and peer identity. Outer reachability is a separate lifecycle with
operations to reconcile a route, reopen a protected socket, resolve an endpoint,
update its address, and observe handshake progress. Full session destruction is
an explicit final operation with a reason, never a synonym for network refresh.

The existing library primitive is only a starting point. The custom `packetBind`
currently fixes the remote address and chooses one socket family at Open; both
Send and receive filtering use that address. A UAPI peer endpoint update alone
is insufficient. The endpoint, accepted-source policy, socket generation and
routing protection must be updated coherently, including IPv4/IPv6 transitions.
Authentication remains the device's responsibility; source-address admission
must not be confused with cryptographic authentication.

| Event | Intended first response |
| --- | --- |
| Packet loss, jitter, temporary blackhole | Preserve flows and device; allow protocol retransmission/rekey |
| Repeated unchanged network callback | Reconcile effective route; otherwise no-op |
| Physical interface/address/gateway or NAT path change | Reconcile/rebind protected UDP while keeping the stack and peer |
| Sleep then wake | Preserve session; reconcile reachability and stale path on wake |
| Endpoint DNS returns same address | No-op |
| Endpoint DNS returns new address/family | Update peer and underlay transactionally; retain TCP identity if server egress state survives |
| DNS-only change | Refresh applicable resolvers/caches and policy; preserve compatible flows |
| Restrictive routing/security rule change | Re-evaluate policy and terminate incompatible flows where necessary |
| Peer offline or UDP blocked | Bounded in-place recovery, then quiet offline/backoff; silence alone does not justify destroying flows |
| User stop or incompatible profile/key change | Explicit cancel/teardown; invalidate all outstanding generations |
| Proven unrecoverable internal failure | Full reset with observable reason and explicit loss of old flows |

One recovery coordinator per session should serialize operations, coalesce events,
use monotonic time and cancellation generations, and distinguish physical offline
from backend failure. Backoff must cap work and probes without making exhaustion
of a network retry budget automatically kill still-valuable TCP state. No incoming
traffic during idle is not failure evidence.

During pauses, retain capture/kill switch and DIRECT/VPN boundaries. Keep buffers
bounded with backpressure; a VPN flow never falls back to DIRECT. Persistent
keepalives can maintain NAT mappings where appropriate, but cannot compensate for
an actual outage or destroyed TCP state. Diagnose path MTU/ICMP failures, asymmetric
loss, retransmission backoff, and queue behaviour separately; avoid blanket timer
increases and extra reliable transport layers that add head-of-line blocking.

Measure two outcomes independently: connection survival and time until useful
traffic returns. Log recovery reason, operation, generation, actual teardown and
result without secrets or application destinations.

Server-assisted path redundancy is a separate extension: alternative paths or
transports can preserve connections only if they retain the same inner addressing,
flow state and server egress/NAT anchor. Switching to an unrelated server or
protocol does not provide this by itself. Surviving a failed egress server requires
server-side continuity/state replication or a separate stable egress anchor.

## Remaining acceptance and limits

This is not an end-to-end Linux desktop/UI or OS TUN acceptance test. It does not
test kernel/legacy WG/AWG, actual NetworkManager callbacks, DNS changes, NAT
rebinding, changing outer IPv4/IPv6/interface, suspend/resume, IPv6 underlay,
PMTU changes, one-way failures, prolonged offline, Android/Apple/Windows, OpenVPN
or Xray. The peer and application server share a private userspace stack; no real
server forwarding/NAT state is exercised. Physical Wi-Fi/mobile behaviour, native
leak protection, device CPU/memory limits and cancellation during native refresh
still need isolated platform fixtures. No recovery behaviour has been modified.

An initial exploratory sequence used a shorter application deadline and had an
inadequate HTTP-server cleanup path. Its incomplete results are not acceptance:
several pauses resumed, one bulk stream exceeded its observation window, and
some WSS sockets hit the fixture deadline. The corrected fixture closes test
server connections explicitly and separates the isolated matrix from successive
outages. Repeated-loss latency remains a distinct investigation item.

Protocol references: [WireGuard protocol](https://www.wireguard.com/protocol/),
[NAT keepalive](https://www.wireguard.com/quickstart/#nat-and-firewall-traversal-persistence),
[WebSocket RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html).
