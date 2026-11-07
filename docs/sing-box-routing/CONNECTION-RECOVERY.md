# Connection-preserving recovery: Linux AWG/WG

Work in progress, based on the verified TCP-dependency change (PR 15).
The new transport operation and native capture prerequisites are implemented;
automatic GUI/watchdog recovery and replaceable network DNS are not enabled yet.

## Ownership boundaries

An established routed session must retain its helper, sole TUN reader, flow
router, FakeIP identity and both private packet/TCP stacks. Changing physical
routes, reopening a protected UDP socket or resolving another address of the
same cryptographic peer must not call Runtime.Close or Network.ResetNetwork.
The latter closes every tracked application connection in the pinned engine.

Explicit user stop/profile replacement and a proven dead backend remain distinct
from a temporary network failure. An IPC interruption alone is not proof that
the service-owned backend died. DNS/command completion must carry generations
so a late result cannot mutate a replacement session.

## Verified foundations

`Transport.RefreshUnderlay` replaces only the protected socket and optionally
the numeric address of the same peer. It keeps the stack and peer configuration,
honours a fixed listen port, selects a fresh automatic port on family changes,
and remains retryable after open failure. A bounded UDP send/gate prevents a
blocked device-network reader lock from wedging recovery or manual disconnect.
This changes neither TCP timers nor application messages.

Each receive generation pins its admitted source. Outgoing packets use the
validated control-plane destination even if a delayed authenticated packet
makes the device remember the retired endpoint. The private helper command
accepts only a numeric address and request ID; it cannot replace keys, policy,
tunnel addresses or the configured server port. Transient failure is an
acknowledgement, never a command to abort the runtime.

Tests with real cryptographic peers preserve one TCP object/server accept across
NAT mapping replacement, outer IPv4-to-IPv6 endpoint migration, failed-open retry
and invalid requests. Configuration hashes, counters and the stack are retained.
A stalled UDP writer plus ten contending senders does not wedge recovery.
The affected Go packages passed three race-instrumented repetitions.

## A second TCP identity: the native application socket

Keeping the private Go TCP stack alone is insufficient on Linux IPv4. OUTPUT
capture marks are applied after the kernel's first source-address selection.
Native WSS/bulk sockets therefore originally used physical `203.0.113.1`.
After removing that address, assigning `.3` and verifying the replacement
protected route, those old sockets stalled despite a live TUN/runtime and UDP
refresh. An input-only local return route restored some download progress but
did not restore bidirectional WSS; it is not the production solution.

Marking before connect's first route lookup instead gives the application's
socket the stable TUN source `172.19.0.1`. The implemented cgroup-v2 connect4/6
programs do this without application changes. They apply only to TCP and the
owner's network-namespace cookie, preserve other mark bits, and leave protected
native sockets exempt. Only BPF link FDs are used: close/process death detaches
our programs; no persistent legacy attachment, foreign-program replacement or
bpffs pin is used. Unsupported kernels/permissions expose limited capability,
not a claim of source stability.

The isolated functional test verified UID 1000, protected sockets, exclusion of
a second namespace, and removal on owner close. Native TUN tests then preserved
the original WSS/TLS sockets through physical IPv4 removal for AWG/WG and inner
IPv4/IPv6, with no application-side marking callback. The same four cases also
passed after removing the physical default route while retaining a route to the
VPN endpoint. Each case retains WS-ID=1, bulk-ID=1 and two server accepts; an
explicit runtime stop still destroys those streams and a fresh start gives
WS-ID=2. These are synthetic isolated namespaces, not physical-device acceptance.

Only the owned TUN includes its input capture mark in IPv4 reverse-path lookup;
physical/global RPF settings remain unchanged. Its private nftables forward
guard prevents proxy replies from escaping onto a physical interface or looping
back into the TUN when the destination is not locally deliverable. Recovery
recognizes the original output-only schema and the complete new schema, refusing
partial or foreign tables before deletion.

## Remaining integration

Network DNS must become a replaceable context separate from application flows.
On physical-network change, cancel in-flight old-generation DNS, reject late
answers and clear real caches; preserve FakeIP and application TCP identities.
Unavailable/ambiguous inventory must pause new DNS without plaintext fallback,
wrong-interface requests or full runtime teardown. Resolver-bus recovery must
reapply only our TUN's settings.

The Linux native recovery owner must coalesce network hints, observe actual
protected endpoint routes (gateway changes need not emit a global NM event),
respect protocol timers and retry without deleting an established session.
Qt's numeric/domain reconnect and stale-peer paths must delegate to that owner.
Initial connection budgets, explicit disconnect and proven helper death remain
separate. Windows/mobile/legacy/OpenVPN/Xray recovery is not claimed by this
Linux routed implementation. Remote TCP/application deadlines, lost server NAT
state and explicit physical-interface bindings remain external constraints.
