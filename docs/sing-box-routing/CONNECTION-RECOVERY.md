# Connection-preserving recovery: Linux AWG/WG

Work in progress, based on the verified TCP-dependency change (PR 15).
The transport operation, native capture prerequisites and independently
replaceable Linux network DNS are implemented. The Linux routed application,
service and helper now share the established-runtime recovery path. Final
installed-service and exact-commit CI validation is required before readiness.

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

## Replaceable Linux network DNS

Real DNS now has a separate generation with its own service registry, resolver
rules, real cache and interface-bound sockets. Its DNS-only Box has no inbounds,
FakeIP database or VPN device; VPN queries borrow the original live VPN outbound.
The main Box retains FakeIP identity, application routing and established TCP.
Outer real-cache hits cannot bypass a suspended generation. Replacement reserves
a generation before native preparation: a later suspension rejects both late
answers and candidates still being prepared. Invalid snapshots never revive the
old network's answers or sockets.

Linux enables this path and serially reconciles native DNS inventory. Unavailable
inventory pauses new real DNS while retaining existing application flows. The
watcher retries after resolver or system-bus failure and reapplies settings only
to our TUN. Explicit numeric DNS does not require native DNSEx inventory. Initial
startup remains bounded; the established owner's transient resolver failures no
longer become fatal Stats errors. The native owner now invalidates real DNS on changes of the protected endpoint
route even when the resolver addresses remain the same.

Tests preserve a real application TCP object/server accept while replacing DNS
addresses, interface bindings, cached answers and DIRECT/VPN domain rules. They
reject late responses, superseded preparation, invalid inventory and plaintext
fallback when encrypted DNS fails. AWG/WG packet-FD tests retain the sole reader,
native protection hooks and the same FakeIP across three DNS replacements, then
verify explicit cleanup. A private D-Bus integration test restarts the synthetic
resolver and the bus, verifies suspension/resumption and keeps the owner alive;
three race-instrumented repetitions passed. It never uses the host system bus.
Run it with `AMNEZIA_RESOLVED_RECOVERY_TEST=1` and `dbus-daemon` available.

After enabling this path, the four native AWG/WG inner IPv4/IPv6 cases again kept
the same WSS/bulk sockets across protected socket refresh, physical IPv4 removal
and removal of the default route (only the VPN endpoint route retained). This
validates the capture/runtime regression path with `--no-system-dns`; it is not
a combined native-TUN/system-resolver failure acceptance test.

## Native protected-route recovery

The Linux owner polls the actual endpoint route with the protected socket mark,
UDP protocol and destination port. Its fingerprint includes the selected
interface, preferred source, gateway, routing table, MTU and interface prefixes;
a generic default-route query is insufficient. Each private netlink socket has
one-second send/receive timeouts, with no global socket-timeout mutation.

After the first handshake, a path change suspends old DNS and probes the current
UDP socket through the same cryptographic peer. The probe respects the device's
handshake rate limit. A fresh handshake ends pending recovery; queued data or a
late response to the previous route cannot cancel a probe still in cooldown.
Missing routes pause socket reopening. Otherwise failed/unconfirmed probes lead
to socket-only refresh with 5-to-30-second backoff; submission/open success alone
is never treated as recovered connectivity. Duplicate hints do not reset the
wait/backoff. The owner respects longer configured AWG protocol wait intervals
and leaves bounded initial connection and explicit teardown separate.

Native acceptance removes the original physical IPv4, removes the default while
a destination route still works, then deletes the original veth pair and moves
to another interface, gateway and prefix. It retains the server's public source
address: an initial fixture incorrectly let the server reply from its private
transit address, which the configured-source filter correctly rejected. The
corrected scenario must retain WS-ID/bulk-ID and two server accepts without any
manual socket-refresh command; real owner counters prove the route was observed.
The existing loss/delay check runs on the replacement interface. Both download
and upload cases are mandatory in the Linux TCP CI script. These isolated tests
do not establish behavior for physical Wi-Fi/cellular drivers or every routing
policy (the lookup does not know an automatically allocated socket source port).

The Linux package CI initially found a separate startup race: explicit DNS had
no inventory fingerprint, so the first watcher tick unnecessarily retired its
already valid generation. That raced a connection using a cached FakeIP after
restart. A before/after installed-service reproduction failed with the old
helper and passed 100 reconnect cycles plus endpoint migration with the fix.
The permanent FakeIP table itself passed restart tests in both runtime modes.

## Application/service ownership and endpoint discovery

The service assigns a UUID to each native runtime and advertises its capability
and liveness. Connected notifications carry that identity, so recovery is bound
before the GUI can observe Connected or receive a queued network event. Status
requests have generations; replies preceding activation cannot bind a new
protocol to an obsolete owner. Cleanup acknowledgements have independent request
IDs and the runtime UUID. A stale GUI cannot stop a replacement runtime.

Network/wakeup notifications and the established watchdog now hint the native
owner. The GUI retains its state across IPC loss and reconnects to the same
service. Only a matching, confirmed dead child permits bounded full recreation;
a replacement owner is abandoned without global GUI route/DNS cleanup. Routed
Linux delegates all OS/DNS ownership to the child and skips legacy GUI stack
reset and saved-route clearing. Explicit user disconnect still waits for real
service cleanup. Numeric routed endpoints use the same acknowledged initial
connection state machine as domain endpoints.

The immutable original endpoint hostname crosses the private activation boundary.
After an unconfirmed path probe, the helper resolves only that control-plane
name through protected fixed bootstrap resolvers, including IPv6. UDP truncation
or failure can retry TCP to the same resolver; application names never use this
path. Validated answers may rotate only the existing peer address, retaining
port, keys, tunnel addresses, routing, FakeIP and TCP objects. Cancellation,
network hints and newer endpoint commands invalidate late candidates. Fresh
handshake nanoseconds distinguish two handshakes within one wall-clock second.
The new target submission is recorded before another route sample, avoiding a
redundant probe/reopen after a successful migration.

The default established-traffic health probe starts after 15 seconds without
receive/handshake progress. This is not a TCP timeout or a teardown budget.
Longer configured AWG waits remain respected, including its rekey timeout.
Absent paths pause reopening; retry exhaustion never releases an established
runtime. Global native interface/route/rule epochs also refresh real DNS when a
non-VPN interface changes while the server route and DNS addresses stay equal.
Explicit wakeup/network hints cover indistinguishable LAN topologies and use
wall time only for DNS-hint debounce; retry/traffic budgets remain monotonic.

Validation includes the real WireguardProtocol/base class, real local IPC,
foreign-owner and obsolete-cleanup rejection, a network callback delivered
synchronously from Connected, IPv6 bootstrap sockets, private D-Bus restart,
changes on another native table, and exclusion of owned capture state from
network epochs. Native domain migration preserves original WSS and bulk sockets
in AWG/WG, inner IPv4/IPv6, download/upload cases with the old front door blocked.
The installed production driver additionally checks the same runtime PID, TUN,
echo/bulk sockets and FakeIP across signal bursts, IPC loss and domain rotation,
with strict protection enabled and disabled. It has no application redial loop.

## Scope and limits

This stage targets Linux routed AWG/WG. Other platform/legacy recovery behavior
is retained. Modern Linux cgroup-v2/BPF support provides stable native TCP source
selection; unsupported kernels expose limited capability. Remote application/TCP
deadlines, destroyed server NAT/state, a cryptographically different peer,
explicit physical bindings and networks with no usable route/transport remain
external limits. Bootstrap is control-plane DNS through the fixed resolver set;
private-only endpoint naming, additional encrypted bootstrap transports and
network-specific NAT64 discovery are not claimed. No host VPN or resolver is
modified by the isolated acceptance fixtures.
