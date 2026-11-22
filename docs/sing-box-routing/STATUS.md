# Implementation checkpoint — automated validation

## Native Apple WG/AWG reader integration — 2026-11-22

The single existing AWG/Xray/routing Go archive now wraps the native `wgTurnOn`
TUN reader with a synchronous packet filter. The pinned upstream ownership entry
is checked before patching; changed/multiple entry points fail the build. Shared
routing is not wrapped. ON has no active filter and native bytes remain native.
OFF registers the Swift DNS controller and rejects IPv6 at that same reader;
non-DNS IPv4, ICMP/opaque native packets and TUN headroom remain unchanged.

The provider prepares/publishes native WG DNS settings through the same
transactional controller as OpenVPN, including adapter settings/path updates.
The filter remains registered across temporary native backend suspension. Stop
first cancels DNS, then joins the native backend, then unregisters/releases the
filter host. Duplicate admission is rejected; unregister joins in-flight
callbacks before host release. Late cleanup uses the original filter lease.
Unchanged DNS is reused during endpoint/settings refreshes instead of resetting
DNS TCP sessions. An OFF settings publication without its callback fails the
connection before the native adapter's five-second proceed-anyway timeout;
late callbacks cannot re-enable that failed generation. Stop also joins already
retiring generations. ON retains its original settings publication path.

Local offline verification passed ten Apple-parent race repetitions of
`dnsguard`, the executable C ABI test including in-flight filter teardown, and
three ownership-overlay Python tests. These used one 2-CPU/4-GiB no-swap
container and existing dependency caches. No packages were downloaded.
New Swift/native filter tests, SDK/full application builds and adapter runtime
acceptance remain pending. Missing native IPv4 interface or original resolver
policy remains a fail-closed unsupported configuration, not silently invented
DNS. Xray and remaining Android/desktop native integration are still outstanding.

## Apple native OpenVPN connection wiring — 2026-11-22

Hosted Actions execution recovered: run `44997772637` at `c2a6e6d` passed all
required jobs. This validates the preceding components/settings tests, not the
connection wiring described here.

Native OpenVPN now calls `NativeDNSController` before publishing its OFF network
settings. Prepared endpoints are staged in the existing packet-flow reader;
ordinary packets retain the native adapter, and the existing IPv6 rejection
remains after DNS dispatch. Publication commits the new generation or rolls back
to the old one. Retired/failed/stopped capture addresses cannot fall through to
the native backend. Normal disconnect, fatal errors and explicit Stop tear down
guards and their operations. ON keeps original DNS settings and routing.

IPv4 forwarding resolves the original server's selected kernel route with a
bounded local RTM_GET request and requires that exact tunnel or currently
available underlay interface. No route/default-network fallback exists. The
kernel lookup runs outside the guard callback queue and cannot revive a
cancelled operation. IPv6 resolver bindings remain unavailable, with local AAAA
NODATA and SERVFAIL for other queries. There is no privileged IPv6 exception.

New hosted tests cover actual Darwin loopback route lookup and controller
prepare-before-publish, per-server separation, IPv6-only upstream rejection,
publication rollback, Stop racing a late settings callback, native packet
passthrough and unchanged ON. SDK compilation and those tests are pending.
This is not physical Apple VPN runtime acceptance or universal-backend support.
Apple native WG/AWG, Xray and the remaining Android/desktop native paths still
need connection integration and adapter-level acceptance.

## Hosted validation unavailable — 2026-11-21

Source `f234c59` adds the per-resolver settings planner and hosted regression
steps; `b7d0517` adds strict IPv4-only OFF upstream validation. Neither revision
has a hosted validation result. A manual dispatch of `sing-box-routing-ci.yml`
was rejected by GitHub with HTTP 422:
`Actions has been disabled for this repository.`
The repository Actions permissions endpoint simultaneously returned
`{"allowed_actions":"all","enabled":true}`; the workflow itself was `active`.
The reason for this external discrepancy is unknown. No Actions policy, account
setting or billing setting was changed. Earlier `11949e6`/`2180e7f` results do
not validate these newer revisions. Apple SDK/runtime checks remain blocked
until hosted Actions execution is restored. Universal native DNS integration
and merge readiness are still incomplete.

## Per-resolver native DNS settings — 2026-11-21

`NativeDNSSettings.swift` prepares a connection-local copy with one IPv4 DNS
capture address per original resolver, preserving order, duplicates, domain
scope and search metadata. Only individual capture /32 routes are added; native
IPv4 routes/settings and the original settings object are not modified. Specific
route/address collisions fail closed; encrypted DNS is not silently downgraded.
IPv6 upstream bindings remain unavailable, while retaining a local endpoint for
AAAA NODATA. iOS 26/macOS 26 resolver failover to the system is disabled.

Resolver paths must be supplied explicitly by the native owner. Apple documents
that system routes and interface scoping supersede included/excluded routes:
https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic
The planner therefore does not guess the DNS scope from a default route or move
all split DNS through the tunnel. Establishing the original scope and publishing
prepared guards transactionally with packet dispatch/teardown are still pending.
The initial planner requires a native IPv4 interface; IPv6-only native interface
capture setup remains to integrate. SDK/settings regression tests are pending.

## Strict IPv6 OFF clarification — 2026-11-21

The user clarified that OFF means all IPv6 traffic, including DNS upstream
transport. The proposed privileged IPv6 native DNS control path was abandoned;
its uncommitted Go prototype and source-binding change were removed. Its local
test logs are historical prototype evidence, not shipping-code acceptance.
No such exception was committed or enabled.

Native DNS integration must use an IPv4 managed endpoint for local AAAA NODATA.
An original IPv6-only upstream is unavailable with OFF; other queries must fail
closed without silently substituting a resolver or underlay path. An existing
multiple-server policy may retain its original explicit selection semantics.
The earlier control-plane preservation requirement below is superseded.
The OFF-only Swift resolver now rejects IPv6 literals (including scoped and
IPv4-mapped forms) before creating an operation, and also rejects hostnames,
unspecified/multicast/reserved IPv4 destinations and NUL-truncated input. New
resolver validation tests are pending Apple SDK execution. ON is unchanged.

## Scoped native DNS transports — 2026-11-20

At `2180e7f`, hosted iOS job `136366795882` passed the iPhoneOS
typecheck, executable Swift/native host test, actual loopback UDP/TCP transport
tests and full app/packet-tunnel builds. The first matrix attempt was not green:
the two macOS ARM jobs never acquired runners (capacity annotations, no steps).
Only failed/uncompleted jobs were resubmitted after inspecting those annotations.
The second attempt also failed to acquire both ARM runners: jobs `136411407621`
and `136411408425` were cancelled without steps, with the same capacity
annotations. The build gate correctly failed; no third rerun of the same code
was requested. The successful iOS job log is preserved locally as
`ci-2180e7f-ios-fetch2.log`; an earlier log-fetch attempt failed at the blob
endpoint and is not a product-test failure. No application packages were fetched.

The transport fixture now also checks idempotent cancellation for both UDP and
TCP after the server receives the query, spanning the retry and deadline windows
and asserting no late callback or reopened connection. This additional test has
not yet run with the Apple SDK.

In `44744543451` at `49d1819`, the new iPhoneOS host typecheck, C client and
executable Swift/native DNS lifecycle test passed. Full iOS app construction
subsequently failed fetching OpenVPNAdapter: GitHub:443 was unreachable for
75 seconds. Windows build job `136317552765` lost runner/server communication
while its build step was in progress; no failed product assertion was reported.
Those failures are retained, not converted into complete package passes.

`NativeDNSResolver.swift` now supplies explicit tunnel/interface/loopback
transport scopes, numeric server validation, same-connection bounded UDP
retries and TCP framing/candidate replies. Legacy through-tunnel APIs remain
only for older OS versions. It does not select another resolver/interface on
failure. Host dispatch now keeps an absolute monotonic deadline across its
queue instead of restarting the timeout after queue delay.

The hosted tests use a loopback-only ephemeral UDP/TCP fixture for first-packet
loss, same-socket retry, fragmented TCP framing, multiple candidate replies,
timeouts and non-query non-retransmission. The original SDK and transport tests
passed at `2180e7f`; these factories still are not invoked by native connection
settings/lifecycles.
Original DNS-route mapping and IPv6 DNS control-plane handling must be completed
before universal NODATA or merge readiness can be claimed.

## Swift native DNS host layer — 2026-11-20

Run `44734415980` at `b0cbffc` passed the complete main matrix, including the
Darwin native DNS C client. The next layer is `NativeDNSGuard.swift`: it owns
the asynchronous host callback boundary, classifies packets without a second
reader, preserves per-query UDP/TCP selection, rejects immediate scope failures,
keeps spurious replies from terminating valid pending work, and cancels requests
before native host release. iOS/macOS targets include the class but no native
connection path instantiates it yet.

The C API gains terminal request rejection so native errors become SERVFAIL
without copying exception messages or waiting for a timeout. Go/C regressions
and a new executable Swift/native-host lifecycle test cover that path. SDK and
Swift runtime validation of this layer remain pending; concrete native DNS
transports, settings publication and protocol lifecycle integration are still
required. This is not universal-backend completion or a merge-readiness claim.
The updated Go/race suite passed ten Apple-parent repetitions and the executable
C client passed locally with rejection coverage. No packages were downloaded.
The Apple Conan recipe now requires the exact new exported text symbols, so
missing native-DNS ABI cannot be mistaken for a compatible archive.

## Native DNS C-client portability follow-up — 2026-11-20

Run `44726482222` at `b573b00` passed every executed lane except the iOS
construction lane's new C-client compilation. The iPhoneOS unified archive,
all new DNS symbols, Swift policy typechecks and the original host packet-flow
ABI test passed before that failure. The C client's Linux-oriented
`_POSIX_C_SOURCE` hid BSD typedefs used by Darwin `resolv.h`; it now requests
the Darwin feature namespace on macOS, retaining the POSIX namespace on Linux.
`-Wall -Wextra -Werror` and all test assertions remain unchanged.
Hosted execution of the corrected native DNS C client is still required.

## Universal AAAA NODATA requirement — 2026-11-20

The user explicitly chose AAAA NODATA for **every backend** when IPv6 is OFF;
native Apple DNS omission is not an accepted limitation. This newly confirmed
criterion blocks merge despite the fully green `8679f05` baseline. The design
and remaining integration work are in `IPV6-OFF-DNS.md`.

The first shared primitive is implemented in `native/routing/dnsguard`.
In-memory packet tests cover UDP/TCP over IPv4/IPv6, local AAAA NODATA without
upstream traffic, scoped A forwarding with transport preservation, failure
without fallback, cancellation and teardown. The native TUN wrapper preserves
non-DNS bytes/headroom and keeps managed AAAA packets out of the original
backend. Ten race-instrumented repetitions passed in one offline 2-CPU/4-GiB
build container with swap disabled. It is **not connected to a shipping native
backend yet**, so universal support and merge readiness are not claimed.

The asynchronous native-exchange bridge and Apple C exports now have ownership
and cancellation coverage. A real C client passed NODATA/scoped forwarding,
passthrough classification, exactly-once completion/release and late-reply
rejection against an archive using the pinned Apple parent Go graph. Initial
offline preparation found the Apple gVisor pin missing from one cache; it was
reused from the existing integration cache without downloading anything.
An unrelated non-Apple header unused-parameter warning was corrected without
weakening `-Werror`. Dependency verification, ten Apple-parent race repetitions
and the ordinary dnsguard/engine/mobile suites passed. The new CI checks use the
actual unified Apple host library and archive symbols. SDK validation, Swift
native-adapter wiring and the other native backends are still outstanding.

No new artifact downloads were made. Existing arm64/x86_64 packages from
`44702509917` (source `8679f05046c55561b76aad7697059988193c3247`) passed local
hash/size/ABI/payload/notice verification for eight APK entries. The report is
explicitly partial; armv7/x86 and desktop/iOS artifacts were not locally
re-audited after downloads were stopped. The all-green hosted source baseline
is main `44702516775` and Android `44702509857`, not evidence for this new work.

## Atomic application-policy DNS replacement — 2026-11-20

Android run `44698056095` at `697a9a8` failed WG/API29 package-reinstall recovery
and an independent WG/API35 cyclic UDP probe; other lanes passed. The retained
API29 snapshot distinguishes history from present state: `dns_available=true`,
`dns_version=2`, three completed/failed queries with last class
`generation-unavailable`. The bounded live log contains no recovery request
or underlay change. Generation 1 is initial publication; the application-policy
update reserves generation 2. This narrows the DNS failure to that update's
freeze-before-build interval, not permanently suspended network recovery.
It does not establish a cause for the separate API35 UDP timeout.

`Runtime.UpdateAndroidApplications` now reserves a replacement generation
without dropping the current DNS/policy. It builds the candidate and atomically
publishes UID membership plus fresh DNS through the existing `replaceWith`.
A failed build retains the old policy; a real network suspension increments
the version, invalidates the candidate and remains fail-closed. Application
updates cannot reopen already-suspended DNS. Network-DNS reload/suspension
behavior is unchanged.

The complete Go engine and mobile suites passed locally. Three deterministic
boundary cases cover successful commit, candidate-build failure and real
network suspension; the new test passed 20 repetitions. A separately retained
red-control source copy restores the old freeze-before-build behavior and
fails specifically at the existing-DNS preparation boundary. The fixed source
and red copy were not conflated. These checks ran in one offline Linux build
container capped at 2 CPUs / 4 GiB total with swap disabled; the Android
emulator was stopped. Race checks and current-source hosted Android acceptance
are still pending. No complete Android pass is claimed.

## Current hosted baseline and recovery evidence — 2026-11-20

At `b56b53f`, main run `44583629056` passed the entire matrix, including both
ARM Mac jobs. Linux-native run `44583629145`, current Android packages and all
other listed supporting workflows passed. Android acceptance `44583612049`
passed 5/6 lanes; AWG/API29 failed after application reinstall and capture
restart in the personal profile. Earlier work-profile failure is retained.
This establishes a repeated restart scenario, not its underlying cause.

The retained diagnostic `dns_last_failure=generation-unavailable` is historical
and does not establish current availability. The snapshot now includes current
generation availability/version, with tests covering both suspended DNS and
republished DNS retaining the historical failure label. Recovery logs retain
only handle/ticket counters, stage and exception class, never profile values,
endpoint names/addresses, credentials or exception messages.

The final logcat snapshot in the latest failure retained only teardown events:
its count limit can lose early selected events amid unrelated system logging.
A targeted live log now starts after adb root, with a 10,000-matching-record
bound, records premature exit, and is terminated/reaped in finally. The file
is explicitly included in the primary artifact allowlist. The existing final
snapshot remains. These are evidence changes only, not a claimed DNS fix.
Hosted validation of the new diagnostics remains pending; no local Go/Kotlin
PASS is claimed. Merge readiness is still blocked by Android recovery, native
Apple AAAA NODATA acceptance and current-source final artifact reconciliation.

## Linux hosted closure and Android capture review — 2026-11-19

Run `44581190296` at `48387b4` passed all six required Linux-native lanes:
AWG/WG namespace capture on Ubuntu 22.04/24.04 and both system-resolver
split-DNS lanes. This validates the pipe-draining harness correction in the
previously failing workflows; their earlier failed evidence is retained.

New Codex finding `4632863609` identified IPv6-OFF capture loss in Android
destination include mode: split compilation removed the /1 capture routes.
The builder now records the explicit full-family capture requirement and
installs it after destination split compilation, stripping IPv6 exclusions
while retaining IPv4 split policy. Protocol setup records the requirement
before its no-split/disabled-split early returns. Missing preference/ON still
uses the existing destination scopes. New JVM regressions cover IPv4-only
include and IPv6 include/exclude policies under OFF.

Local Gradle attempts hit the 4-GiB laboratory cgroup limit, including after
reducing guest allocation to reserve build overhead; no local Kotlin PASS is
claimed. Limits were not increased and no second VM ran. The emulator was
OOM-terminated; its stale lock files were preserved under
`.before-merge-prep-oom` before retry. Hosted Kotlin tests and actual Android
packet acceptance remain required for this correction. No merge is authorized
by this readiness checkpoint.

## Merge preparation: Linux helper shutdown — 2026-11-19

Both Linux acceptance drivers waited for helper exit without draining its status
pipe. The helper emits periodic status on the same select-loop thread that
consumes `stop`; a full stdout pipe can therefore prevent it from reading stop.
The drivers now use `communicate` to deliver stop/EOF and drain output together.
The original 15-second bound, zero-exit assertion, and distinction between
graceful stop and command-pipe-loss abort remain unchanged. No production
networking or acceptance assertion was relaxed.

Five real-process/pipe tests passed in the single constrained API29 laboratory
container (2 CPUs, 4 GiB total memory including emulator overhead, swap disabled).
The negative control fills a 4-KiB pipe: the old wait times out, then draining
allows the exact same process to finish. Tests also check graceful stop, EOF,
nonzero exit rejection and timeout rejection. This reproduces a harness failure
mechanism; the complete hosted Linux lanes must still establish whether it
accounts for their previously retained failures.

Android run `44543994486` at `cf7cf31` passed 5/6 lanes. The remaining AWG/API29
failure is work-profile package-reinstall recovery; the personal-profile case
passed. Its new network-event snapshot shows VPN networks 104 -> 105 while
Wi-Fi underlay 100 stays unchanged. TCP refusal/DNS timeout and
`generation-unavailable` remain observations, not a proven root cause.

Main run `44534261050` at `489318b` has now completed: iOS compilation, Linux,
Windows, Android build/core lanes and Intel Mac checks passed. The only
non-success test jobs were ARM Mac core and TCP recovery (`135596073712`,
`135596073944`): both had empty runner names and no steps. GitHub annotations
explicitly report “The job was not acquired by Runner of type hosted even after
multiple attempts” and macOS arm64 capacity constraints. This establishes an
infrastructure cancellation, not a successful ARM check or a product failure.
The final build gate correctly remained red. Android and Linux-native failures
in the separate workflows below remain unresolved.

## Hosted failures at `489318b` — 2026-11-19

Android run `44534249506` failed three lanes; logs and all six artifact bundles
are retained separately from successful evidence. WG/API35 timed out receiving
VPN UDP during session 94 of cyclic acceptance. WG/API29 reached the personal
application TCP probe but got ECONNREFUSED; its snapshot also reports two DNS
failures with last classification `generation-unavailable`, not an established
cause for the TCP refusal. AWG/API28 passed its ordinary compatibility test,
then timed out uninstalling the instrumentation APK before OpenVPN testing.
No OpenVPN packet failure is established by that setup timeout.

The network-events snapshot added earlier was omitted from the main acceptance
artifact allowlist (the other subdirectories upload all logs). The allowlist
now includes that exact non-fixture log. This repairs evidence retention only;
none of these acceptance failures is claimed fixed or retried unchanged.
The separate Linux native run `44534261084` also failed: inspected namespace
and AWG system-resolver jobs timed out waiting for child shutdown; a WG
system-resolver job failed uploading artifacts. Other failed namespace lanes
still need individual inspection. Main app/iOS compilation was still running
at this checkpoint. Subsequent local tests must use one 2-CPU/4-GiB VM.

## Codex review follow-up — 2026-11-19

Run `44525956279` at `9cbc7f0` passed every required lane except the iOS app/
extension compilation. The SDK diagnostic identifies an incorrect override
parameter type in the new native capture guard: the superclass accepts
`NETunnelNetworkSettings?`, not `NEPacketTunnelNetworkSettings?`, with a
Sendable completion handler. The override now matches that signature and
conditionally casts packet settings before applying capture; nil/base settings
are forwarded unchanged. A new hosted build must validate the correction.
The previous Intel TCP timing failure did not recur; its cause remains unclosed.

The four findings against `057b7a5` were confirmed by inspecting their real
call paths. Android DNS overrides now precede installation of the global AAAA
NODATA rule, retaining FakeIP priority; the complete Go engine suite passed
locally with `with_gvisor`. Linux Xray establishes service TUN ownership before
launching tun2socks, rather than adopting an existing interface after STACK
readiness. Apple OpenVPN receives the explicit preference and retains full
IPv6 capture without site/provider exclusions when blocking; the transport
endpoint remains exempt.

Native Apple WG/AWG now receives the preference outside the shared-routing
conditional. Explicit OFF removes IPv6 AllowedIPs and site exclusions from
the backend configuration, while every adapter network-settings publication
retains full IPv6 capture (including legacy profiles without an IPv6 address).
The sanitized configuration is also the saved endpoint-recovery configuration.
Missing preference still defaults ON; shared routing retains its existing policy.
New Swift tests cover policy/default selection, backend prefix filtering,
full capture, endpoint preservation, repeated settings and IPv4 preservation.
These Swift/Apple SDK tests and the real Linux Xray path still need hosted
verification; no local Mac runtime or physical iOS acceptance is claimed.
Native WG does not use the shared DNS interceptor: its AAAA NODATA behavior is
not established by the peer/capture fix and remains a separate acceptance gap.

Run `44510562002` completed with Linux (including production IPsec update),
Windows, iOS and Apple TCP recovery passing. Its remaining failure is Intel
`TestMaturePathMTUAndTCPRecoveryWorkersRetainTCP`; the failed log is retained,
and its cause is not yet established. Android run `44510551649` passed all
six lanes; this alone does not close the earlier intermittent API29 TXT failure.

## IPsec registry pin repair — 2026-11-19

Run `44501519812` at `cfc66f0` preserved the missing reason: all standard
container preflight fields matched, but Docker failed at `FROM` because OCI
index `21f2a1b28dbbe69c4331571941df548eee2f4e1cba16af8b161248d66db8d490`
is no longer registry-resolvable (`manifest unknown`). No cutover occurred.
The same digest failure was independently reproduced with registry access.

The replacement is OCI index
`78ea73fb726bc97ccb8c592df88030fe44cb962bdd8cb6cd4da53630bc199374`.
Registry bytes, child manifests and configurations were hash-verified for
amd64, arm64 and arm/v7. All three advertise revision `5ff51748` and Libreswan
5.4.2. The genuine upstream commit is
`5ff51748cd5889072fd0ee5da55262d779441de5`; its Dockerfile declares the same
version. The amd64 image was pulled by digest and executed without network,
capabilities or a writable rootfs: `ipsec --version` returned `Libreswan 5.4.2`.
ARM execution is not claimed. No mutable-tag fallback or TLS bypass was added.
Hosted update/rollback and unchanged-client packet verification remain pending.
As with any third-party pin, continued registry retention is externally owned.
Android artifacts now also retain the selected network callbacks via a final
logcat snapshot, avoiding loss when initial `adb root` restarts adbd. This is
additional evidence collection for the unclosed API29 TXT failure, not a DNS fix.

## Hosted follow-up at `cd99b32` — 2026-11-19

Android run `44491504894` passed both complete API35 lanes, both API28 lanes
and AWG/API29. The strengthened OpenVPN scope regression passed in hosted CI.
The remaining WireGuard/API29 failure is the initial personal-profile TXT
request (`uid=10148`), before managed-profile acceptance begins. Preserved
diagnostics include `generation-unavailable`; the precise triggering event is
not proven. The unchanged, hash-verified hosted `cd99b32` APK subsequently passed
both personal and managed profiles locally, including a cold-start experiment.
No DNS behavioral correction or final Android green-gate claim is made.

Main run `44491513666` completed its Mac ARM/Intel, Windows, iOS and Android
lanes successfully. Linux stopped at the production SSH IPsec test: the forced
post-cutover failure expected `rolled_back`, but received an earlier `rejected`.
The updater redirects its reason to a transaction log that was lost when the
owned nested daemon was removed. The lab now emits bounded, credential-redacted
transaction output and a non-secret preflight snapshot on an unexpected result,
before preserving the original assertion. Two diagnostic-safety tests pass.
This is diagnostic preservation, not an IPsec fix; the original failure remains FAIL.
PR remains draft; source/package reconciliation still depends on the final gates.

## OpenVPN final-route publication — 2026-11-19

In the single owned API28 VM (laboratory total limited to four CPUs and 8 GiB,
no swap), the unchanged hosted APK from merge source
`6dc7c3479fc02aac89ef360ecbfcab47eff797e0` reproduced the IPv6 scope failure
after the AWG compatibility prelude and repeated OpenVPN scope transitions.
The original socket used NATIVE; three fresh diagnostic connections one second
apart then used VPN without changing routes. Bounded header-only metadata
confirmed the initial native loopback path and later `tun-ovpn3test` ingress.
The original assertion remained FAIL.

Android 9 primary source confirms that the LinkProperties getter can expose
the new snapshot before netd finishes installing routes, while the callback
follows route installation. The correction waits for publication of the final
TUN's complete addresses/routes before returning its descriptor to OpenVPN.
It rejects stale-agent/intermediate-interface observations, closes the TUN on
failure and supports disconnect cancellation. It does not bind test sockets,
flush caches, add synthetic addresses or alter IPv6 scope/server capability.

The final local JVM-dex prototype passed the AWG prelude plus all 32 IPv4-only
and 24 dual-stack cases: eight scope cycles, eight independent TCP probes per
destination, UDP, loopback and both original IPv4 streams (2016 IPv6 assertions).
Six publication-state and five protocol-policy JVM tests passed. All non-dex
payload bytes were verified identical to the hosted APK. This is explicitly a
local prototype, not a production package from a pure source commit. Hosted
source-coherent APK acceptance is still required.

A rejected capture-source prototype passed its IPv4-only cases but failed a
later dual-stack case. Its patch/artifact/failure evidence remains preserved;
none of its synthetic-address code is retained in production.

## Retained Android socket attribution — 2026-11-18

Follow-up run `44350559015` at `a2f4a62` passed both complete API35
lanes (including retained TCP), both API29 lanes and WireGuard/API28.
AWG/API28's shared-core compatibility step also completed, but its subsequent
OpenVPN IPv4-only `stale-full` case failed: `fd99::4` returned `NATIVE`.
The live snapshot contains a `tun0` unreachable IPv6 default and UID 10088
capture rule, yet the offending TCP socket used native source `fec0::…`
and mark `0x40065`. This reopens the scope-change/cache failure described in
`scripts/routing/android-openvpn/README.md`; the previous passing runs do not
establish its elimination. No cache flush, forced VPN binding of native-scope
probes, blind rerun or acceptance relaxation is an approved fix. Final Android
acceptance and PR readiness remain blocked.

Run `44346633233` at `9b97207` passed five of six lanes. AWG/API35
failed during retained warmup with session 107 still alive, no capture refresh
and no pending/failed DNS. Preserved pre-cleanup Android events show cellular
network 209 becoming inactive at 16:31:30.915, then Netd destroying one socket
for that netId at 16:32:00.914; the Java abort followed at 16:32:01.990.
The surviving media socket carried Wi-Fi netId 100. This implicates test-owned
sockets inheriting different underlay netIds under the VPN-owner UID.

The retained shared-core probes now explicitly bind each original socket to
the VPN Network identified by its capture address before connecting. There is
no reconnect, process-wide binding, timeout increase or observer relaxation.
OpenVPN split-scope probes remain implicitly routed. Hosted verification is
still required; this is not a final acceptance or PR-readiness claim.

## Android DNS stall investigation — 2026-11-18

Run `44326437543` at branch source `9ace22a` passed five Android lanes.
AWG/API35 failed with two real-DNS requests still pending for 4001 ms before
the application TCP connect timed out; the peer did not receive its TCP SYN.
This establishes a pre-connect DNS stall, not a slow Android owner lookup.
The exact location of the original lost/stalled DNS reply is not yet proven.

A deterministic real-UDP-socket regression drops the first DNS datagram:
the pinned UDP transport does not retransmit and reaches the caller deadline.
The shared-core UDP decorator recovers by issuing at most three copies over
the same transport, one second apart. The original attempt remains valid;
first DNS reply wins, including NXDOMAIN/NODATA. Caller cancellation/deadline,
resolver selection and path are preserved; non-query operations are not retried.
The full local Go engine suite and focused real-socket/retry regressions passed
without QEMU or Android emulators. Hosted APK acceptance of this correction
is pending; no final green-gate or PR-readiness claim is made.

## Hosted continuation — 2026-11-17, final gate still open

The user subsequently authorized push, PR updates and hosted Mac checks.
Local Mac execution remains excluded. PR #18 remains draft; no merge is
authorized. The dated local checkpoint below is historical, not current CI status.

- Native Darwin production Qt route adapter: run `44073792451`, source
  `941715d011fd52e52ec7c7915d3b7263d964a545`, PASS on macOS 26 and macOS 15 Intel.
  Original TCP survives A→B→A; new TCP/UDP use the selected paths; exact TCP
  accept counts are A=2/B=1 and owned TUN cleanup passes. This is not full
  production OpenVPN integration or physical network handover acceptance.
- Main run `44142519288`, source
  `ca9fb945aa3ae4f6c4209b0aff71efa4a1f43353`: Linux client lane PASS, including
  production SSH IPsec update/rollback with unchanged independent strongSwan
  client traffic and subsequent Linux acceptance. Production IPsec now pins
  upstream OCI index `21f2a1b28dbbe69c4331571941df548eee2f4e1cba16af8b161248d66db8d490`
  (revision `f48cd8db`, checked amd64 Libreswan 5.4.1).
  Overall first attempt FAIL: Intel Apple TCP recovery took 439 ms against
  the unchanged 250 ms bound; ARM jobs were cancelled. Failed evidence is retained.
- Android run `44153915121`, source
  `8d232fc`: both API28 lanes and AWG API29 PASS after correcting shell scope.
  WG API29 app-policy and both API35 full lanes FAIL. API35 fails during
  reconnect cycles with missing TCP/UDP responses; these are unresolved failures,
  not successful retries or physical-device results.

Hosted artifacts and later source fixes do not relabel the local `93aef02`
packages below. Final full-gate success and artifact reconciliation are pending.

## Default-on IPv6 preference — local acceptance, 2026-11-16

The user removed historical OpenCode/Telegram incident attribution from the
completion requirements and requested a default-on IPv6 switch on every
platform. This is new product work, not covered by the earlier checkpoint.

The preference is stored separately from server capabilities, included in
backups, defaults to ON for old installations/backups, and applies on the next
connection. OFF must retain capture and reject IPv6 rather than create a native
bypass. The shared AWG/WG compiler rejects captured IPv6 before app/destination
rules and returns AAAA NODATA while retaining IPv4 DNS. Android and Apple NE
session builders pass the preference even when split DNS is configured.
OpenVPN, Xray and native desktop WG paths have corresponding connection-local
policy changes. Native Windows IKEv2 uses an independent dynamic WFP policy
when OFF; its IPv6 RAS default-gateway option is enabled when ON.

macOS OpenVPN dynamic-host capability is now source-enabled as requested, with
the existing Darwin adapter. No Apple SDK/native execution is claimed.
macOS tests remain excluded by the user's explicit decision.

Production package source is `93aef020f0ae6ff610d98a9cd5ecd50ddd2eb52d`;
Android acceptance harness is `66993d8e15660e47de74fd6b4a9172f888b4f859`
(test-only addition, not a package rebuild).

Locally executed checks:
- Four ordinary Android debug ABI packages: signatures, 16-KiB alignment,
  native pins/notices and Qt payload binding PASS.
- Actual x86_64 APK on API35, AWG and WireGuard: default/explicit IPv6 ON,
  OFF AAAA NODATA, cached FakeIP/ULA/NAT64 TCP+UDP rejection, IPv4 VPN/DIRECT
  preserved and independent observer counters unchanged.
- Full Android AWG and WG acceptance PASS, each including 100 connection cycles,
  old interactive/media TCP recovery, aged upload MTU, live per-app DNS/routing,
  IPv6 scope and always-on/lockdown. These are emulator, not physical-device or
  battery results.
- Linux ordinary IFW installer, 32 Qt targets, and installed-service acceptance
  on Ubuntu 22.04/24.04 PASS. Each installed run includes 100 resolver cycles,
  endpoint migration, AWG/WG preserving recovery with strict policy on/off,
  helper crash recovery and OS-state restoration.
- Installed Linux OpenVPN matrix PASS: full/include/exclude, legacy/API and
  stale-capability cases with original IPv4 TCP retained.
- Windows ordinary MSI/EXE builds, 31 Qt targets, actual installed-service
  acceptance and uninstall PASS for both installer formats.
- Windows installed OpenVPN full/include/exclude, API, legacy and stale-capability
  canonical gates PASS. Include route-preservation and the independent native
  IPv6 preference gate PASS: OFF survives KillSwitch disable, IPv4 remains
  usable, IPv6 is restored after policy removal.

Earlier failed attempts are retained separately, not overwritten: a WG fixture
without native DNS 1053, Linux export-mode/probe packaging omissions, and Windows
fixture IPv6/guest-clock setup failures. TLS validation was not weakened.
The original WG run changed CPU limits mid-run and is not performance-parity
evidence. Final AWG/WG retries used the stable reduced resource budget.

Apple SDK/native execution remains NOT RUN; no claim of native macOS/iOS
acceptance or a newly built Apple package is made. End-to-end IKEv2 negotiation
and physical-device handover are not established by the independent WFP gate.
No push, hosted CI, PR-ready transition or merge was performed.
Earlier artifact/checkpoint sections below are historical and retain their
original source attribution. Final artifact reconciliation is tracked separately;
local green results do not authorize publication or removal of PR draft.

## Historical pre-preference continuation — 2026-11-16

The current task excludes testing on macOS by explicit user decision. Missing
macOS execution is therefore not a blocker for this task, but remains **NOT RUN**,
not a successful native check. At the checkpoint below, desktop OpenVPN dynamic
IPv6 updates on macOS were disabled; the Darwin adapter had not been compiled with the Apple SDK
or validated against the kernel. Portable policy tests on Linux do not establish
either result. Apple and physical-device results below are historical and must
not be applied to the current source.

Current source checkpoint: `2f6f36d791b1eec1bc9cc374ef3df197f87f7d44`.
The Linux Go suite with `with_gvisor`, the full race suite using the existing
race-only dependency preparation, and `go vet` passed using Go 1.27.1.
The current Linux Qt routing build and its two CTest targets passed, as did the
three Python regressions for Android host compatibility and evidence validation.
These are source regressions, not newly built application packages.

Available ordinary artifacts retain their original provenance:

- Android: all four ABI APKs at `7795b41`; complete AWG/WG 100-cycle acceptance
  remains attributed to `9a64032`, with backend byte-equality and focused later
  APK acceptance recorded separately.
- Linux: installer at `7795b41`; installed-service acceptance on Ubuntu 22.04
  and 24.04 includes 100 resolver cycles and 12 OpenVPN cases on each.
- Windows: MSI/EXE at `4bcde28`; both installed-service checks and uninstallation
  passed. Native OpenVPN acceptance covers ten profile cases, 80 TCP/UDP probes,
  six retained TCP connections and foreign-route ownership. The independent
  100-cycle helper run belongs to earlier `dbff27f`, not these installers.

Historical OpenCode/Telegram failures are not causally resolved by synthetic
fault tests. No release, push, PR-ready transition or merge is established by
this checkpoint. The full-plan audit is still in progress.

## Continuation — 2026-10-27

Production source `d64d8af796602ace13cc971df9c19b05615fd2da` fixes the review's
AWG 3.1 persistent-keepalive regression. Desktop, Android and iOS preserve
range strings such as `25-35`; the shared core validates using the pinned AWG
parser and accepts older numeric JSON. Regression tests cover JSON/UAPI
round trips, actual device range retention, desktop profiles and mobile preflight.
All local Go packages passed with `-race`; module verification also passed.

The [full platform matrix 40497706736](https://github.com/StannisMod/amnezia-client/actions/runs/40497706736)
passed all 20 jobs, including the installed Linux/Windows packages, all four
Android ABIs, unsigned iOS, three race-test hosts and eight cross-compile lanes.
[Windows native acceptance](https://github.com/StannisMod/amnezia-client/actions/runs/40497706686)
and [Linux performance comparison](https://github.com/StannisMod/amnezia-client/actions/runs/40497706626)
also passed.

The first independent Linux capture run timed out during reconnect stress;
the first Android emulator run passed 100 reconnects but timed out on the
subsequent legacy AWG transition. Both original attempts remain **FAIL**.
Without production changes, [Linux attempt 2](https://github.com/StannisMod/amnezia-client/actions/runs/40497706716/attempts/2)
and [Android attempt 2](https://github.com/StannisMod/amnezia-client/actions/runs/40497706698/attempts/2)
passed their complete suites. The timeout causes are unresolved; these passing
repeats do not establish that the intermittent failures are fixed.

The independent installed-Linux diagnostic was still pinned to historical
package run `39966881951`. Its source-equality guard correctly rejected the
new production source before acceptance ran. CI commit `0fddbfa` replaces the
pin with selection of a successful package with identical production sources,
retaining manifest-source, SHA256 and source-diff checks without substituting
the packaged helper. The independent repeat
[40505160583](https://github.com/StannisMod/amnezia-client/actions/runs/40505160583)
**passed** with the current package and matching production sources.

The feature remains opt-in and experimental; the physical-device, signed iOS
and other acceptance boundaries recorded below remain in force. PR #1 is ready
for review; it has not been merged or released.

## Continuation — 2026-10-23

Actions were re-enabled by the repository maintainer. The current production
source is `5fd7a8e0ce7a91455a971e61b11688b281815216`; later commits update CI
provenance and documentation. **The full build gate passed**, including all
20 jobs of [39966881951](https://github.com/StannisMod/amnezia-client/actions/runs/39966881951).
The table below supersedes the historical
checkpoints retained after the separator.

| Gate | Current evidence |
| --- | --- |
| Core race tests | **PASS**, Linux, Windows and macOS, [39966881951](https://github.com/StannisMod/amnezia-client/actions/runs/39966881951) |
| Core cross-compilation | **PASS**, all eight architecture lanes in the same run |
| Android APK compilation | **PASS**, arm64-v8a, armeabi-v7a, x86 and x86_64 in the same run |
| iOS app and Network Extension | **PASS**, unsigned compilation in the same run; signed runtime remains untested |
| Linux client and installed package | **PASS** in the same run, including 26 Qt tests, all 61 dependency notices, 100 system-resolver reconnects, resolver reset repair, strict Kill Switch toggles, application scope, IPC reconnect, helper crash/recovery and exact DNS/route restoration |
| Independent Linux package repeat | **PASS**, [39972050403](https://github.com/StannisMod/amnezia-client/actions/runs/39972050403), matching package SHA256 and production source; installed helper was not replaced |
| Windows client, MSI and EXE | **PASS** in run 39966881951, including Qt regressions, installation, actual LocalSystem service acceptance, dependency notices and removal for both installer types |
| Android emulator policy and 100 reconnects | **PASS**, [39972740869](https://github.com/StannisMod/amnezia-client/actions/runs/39972740869), host APK from `5fd7a8e0` with current native JNI payload from production-equivalent `1861d55e`; includes OS always-on/lockdown and legacy AWG transitions |
| Native Linux and Windows capture | **PASS**, [39772229380](https://github.com/StannisMod/amnezia-client/actions/runs/39772229380) and [39772229355](https://github.com/StannisMod/amnezia-client/actions/runs/39772229355); native production capture source is unchanged |
| Physical devices / signed iOS runtime | **NOT RUN**; see the acceptance boundaries below |

The Linux strict-firewall fix permits the reserved capture mark through the
legacy strict chain alongside the existing TUN and protected-socket exceptions.
The owned routing guard still blocks captured traffic between sessions.
The earlier diagnostic [39966881917](https://github.com/StannisMod/amnezia-client/actions/runs/39966881917)
intentionally tested an older Qt package with the current helper: its strict
probe failed, adding the capture-mark exception restored traffic, and the run
retained FAIL. It is causal negative evidence, not acceptance of that old package.
The new package passed without this diagnostic override. Its rescue report is
`CANCELLED_AFTER_ACCEPTANCE` with zero recovery operations. Across the 100-cycle
stress, the same service PID retained 15 handles and 12 threads; observed RSS
changed from 57.8 to 58.0 MB. Container results do not establish physical-host
network handover or hardware resource behavior.

The Darwin fixture now uses an explicitly configured loopback address. iOS CI
builds dependencies from source without the optional unavailable Conan mirror;
libagw now uses the same pinned Go 1.27.1 recipe as the other native components.
Upstream libagw race tests and its C/C++ archive smoke tests passed locally.
Local routing race tests, vet, workflow actionlint and script syntax checks also
passed. These do not replace the platform-specific acceptance results above.

The feature remains experimental and opt-in. Signed iOS runtime requires
matching app/extension provisioning and hardware. Android emulator acceptance
rebuilds the native JNI payload and records both source SHAs and APK checksums;
it does not claim to test an unmodified release APK. Android 9 lockdown-query
restrictions and physical-device policy behavior remain untested. Physical Android Wi-Fi/cellular
handover, sleep/wake, complete GUI interaction and unaffected protocol regression
acceptance remain separate work. The measured Linux data-path comparison below
shows overhead and does not establish cross-platform performance parity.
The public draft [PR #1](https://github.com/StannisMod/amnezia-client/pull/1)
collects the work for review. No merge or release has been performed.

---

## Continuation — 2026-10-22

Android emulator run `39771504529` at `ac06b611` passed traffic, native QUIC,
100 reconnects, resource checks, invalid-start recovery and legacy transitions.
It no longer crashed during policy changes, but remains **FAIL**: repeating a
routed start under lockdown timed out waiting for a rejection. The service now
rejects that policy before checking/launching VPN consent and explicitly emits
its unchanged disconnected state, so a repeated rejection does not depend on
StateFlow producing a duplicate value. New APK/emulator evidence is required.

Installed-service CI runs exceeded their configured budgets while the runner
was globally captured by a test VPN. Loss of the runner control plane is a
possible cause, not a proven product diagnosis. New disposable Linux runs arm
an independent local 420-second rescue before network changes. It uses existing
Qt strict-off, service deactivation/stop and owned-helper recovery operations;
it never flushes global network state. Triggered rescue records failure and
cannot turn acceptance green. A cancellation test verifies that a disarmed
watchdog executes no recovery operations. Reports include `.rescue.json`.

The Qt service also preserves the standardized resolver error-name category through IPC without exposing its error body; its compilation needs a fresh client build.

An independent x86_64 Android package lane uses the existing deploy script and
pins to supply a compatible emulator host without waiting for desktop runner
recovery. It is not a replacement for the full four-platform build gate.


### Latest observed gates

Shipping source was changed at `cd9d8305`; subsequent commits through `afd9375b`
change only disposable fixtures, test scripts, performance CI and documentation.
A path comparison confirms the client, deploy scripts and production routing
packages are unchanged since that source fix.

| Gate | Latest observed result |
| --- | --- |
| Linux native capture | **PASS** at `afd9375b`, [run 39772229380](https://github.com/StannisMod/amnezia-client/actions/runs/39772229380): full TCP/UDP/QUIC, IPv6, application scope, virtual uplink failover/outage recovery, 100 reconnects, pipe loss, hard crash, explicit recovery and exact native-state restoration |
| Windows native capture | **PASS** at shipping source `cd9d8305`, [run 39769773465](https://github.com/StannisMod/amnezia-client/actions/runs/39769773465) |
| Core race suite / cross-compilation | **PASS** in all three desktop test lanes and all eight architecture lanes of [39769773545](https://github.com/StannisMod/amnezia-client/actions/runs/39769773545) |
| Android APK compilation | **PASS**, all four ABI jobs of run `39769773545`, including current production Kotlin service changes |
| Android policy/emulator acceptance | **FAIL**, [39771504529](https://github.com/StannisMod/amnezia-client/actions/runs/39771504529); repeat-lockdown rejection fix requires a new compatible APK/emulator run |
| Installed Linux resolver stress | **NOT ACCEPTED**: [39769773506](https://github.com/StannisMod/amnezia-client/actions/runs/39769773506) cancelled with logs unavailable after exceeding its budget; new runs use independent local rescue |
| Full Windows / unsigned iOS clients | **IN PROGRESS** in run `39769773545`; prior build passes are historical evidence, not a completed new matrix |
| Linux comparative performance | **PASS** at `35e949c4`, [39771128512](https://github.com/StannisMod/amnezia-client/actions/runs/39771128512), with source SHA and binary checksums in the JSON report |
| iOS signed runtime / physical mobile devices | **BLOCKED / NOT RUN**: matching signing/provisioning and physical hardware still required |

The second performance run measured legacy/routed median throughput of
818.38/635.94 Mbit/s, CPU seconds/MiB of 0.01375/0.02375, and maximum observed
RSS of 12,164/46,464 KiB. Routed/legacy ratios were 0.777 throughput, 1.727 CPU
per MiB and 3.820 RSS. First verified transfer after starting the backend took
0.123/1.136 seconds. These are measurements on one disposable CI machine;
absolute rates vary between runs. No production performance parity is claimed.


At `ac06b611`, native Linux run `39771504567` completed traffic, native QUIC,
application scope, virtual uplink failover, outage fail-closed/recovery,
100 reconnects, pipe-loss/crash guards and explicit recovery. Its overall
result is still FAIL: the final exact route comparison found the fixture's
`203.0.113.0/24` route missing from table 222. Bringing eth0 down had removed
that route in the kernel; the simulated network manager now reapplies its own
static route on eth0 restoration, just as it already reapplies the default.
The final exact comparison is retained; this is not an exemption for route leaks.


Follow-up evidence: [performance run 39770515696](https://github.com/StannisMod/amnezia-client/actions/runs/39770515696)
PASS at `0232050c` (artifact `12421039401`). Median throughput: legacy
551.44 Mbit/s, routed 437.90 Mbit/s; routed/legacy throughput 0.794,
CPU seconds/MiB 1.647, observed RSS 4.005 (11,616 vs 46,524 KiB).
This is one 4-vCPU CI-host data-path comparison at MTU 1280, not cross-platform
parity. That report's source_sha was null because sudo stripped the environment;
workflow source SHA and binary checksums establish its provenance. `35e949c4`
passes source SHA explicitly and records time to the first verified transfer;
the old initialization timers end at different milestones and are not a valid
startup-latency comparison.

Linux run `39770515900` failed the new raw-AWG probe **before native capture**,
after ordinary TCP/UDP underlay observer probes passed. The peer received 12
outer datagrams and submitted 3 responses, but no inner flow reached it.
Run `39770943808` identified the cause: the client expected the fixture endpoint
`198.51.100.2`, but all observed AWG replies came from `10.0.2.2`. The client
correctly rejected the different endpoint. The disposable peer now explicitly
binds its outer socket to the off-link observer address; production endpoint
validation is unchanged. A local authenticated loopback-secondary-address test
passes with race detection. Keep the full Linux native gate FAIL until this
correction and the subsequent handover/crash/restoration scenarios pass.


Resumed at `1f56c109d9bc3596f2bba8ae75066408385ccb16`.
The latest source matrix [39624238843](https://github.com/StannisMod/amnezia-client/actions/runs/39624238843)
passed Android APK builds for all four ABIs, unsigned iOS app/extension,
Windows app/service/installers, desktop core tests and package cross-compiles.
Linux compiled, packaged and passed Qt tests, but its installed-service resolver
stress failed with `system resolver link configuration failed`. Therefore the
aggregate build gate is **FAIL**, not a green four-platform acceptance.

- Windows native acceptance: PASS, run `39624238817`.
- Linux native acceptance: FAIL, run `39624238708`, waiting for a helper event.
  The new diagnostics distinguish `ready` from `connected` timeouts and verify
  native observer reachability before capture. Underlay/handover acceptance
  remains open.
- Android emulator: FAIL, run `39624238657`. Traffic, 100 reconnects and the
  routed/legacy/routed transition passed, then a device-policy transition
  triggered a foreground-service `SecurityException`. The failure snapshot
  masked the instrumentation failure when the service process disappeared.
- Linux performance: FAIL, run `39624238994`; the baseline installer could not
  load `libxkbcommon-x11.so.0`, so no performance comparison was measured.

This continuation adds the missing installer runtime dependency, handles
foreground-promotion authorization loss without an uncaught exception,
restores emulator VPN consent after removing device-owner always-on policy,
and preserves the original instrumentation failure if resource collection
fails. Resolver initialization now bounds `NoSuchLink` retries across GetLink
and all setters; other D-Bus failures remain immediate and expose only their
error name, never their body. The exact cause of the earlier generic resolver
failure is still unproven; native CI must establish it.

Local Go 1.27.1 complete race suite (`-count=3`) PASS, including setter-race,
permanent-error, cancellation and error-redaction tests. Local native capture
is BLOCKED by forbidden netlink sockets and absent `/dev/net/tun`. The source
changes need new native/package/emulator CI evidence. No merge or release.

## Current verification — 2026-10-21

Resumed from `ff86843cbe35e7e8bc9fbcdec0d4a627cf425e57` on the existing
`feature/sing-box-routing` branch. Verified base:
`ddde43635e957ebf042d92787489da72d3394019` (`dev`).
Production fixes in this continuation: `e455c6a9`, `ff7016b9`, `ab782ce1`, `18efe265`.
No dev merge, server modification or release publication was performed.

The feature remains experimental and off by default. Source integration,
compilation, controlled native tests and physical-device acceptance are separate
claims. The four-platform handoff is **incomplete**.

| Check | Latest verified result |
| --- | --- |
| Android APKs | PASS at `18efe265`, [run 39583806899](https://github.com/StannisMod/amnezia-client/actions/runs/39583806899): all four ABIs, including JNI payload inspection |
| iOS unsigned app + extension | PASS at `ff7016b9`, run 39555388790. No signed IPA or device acceptance |
| Linux app/service/RUN + Qt regressions | PASS at `18efe265`, run 39583806899, and rebuilt/tested again at `395c491f` in [run 39584835912](https://github.com/StannisMod/amnezia-client/actions/runs/39584835912). All five settings/rule/application regression targets PASS |
| Windows app/service/EXE/MSI + Qt regressions | PASS at `ff7016b9`, run 39555388790. MSI log confirms installation success (exit 0). The subsequent installed-service step hung until the 120-minute job limit; EXE installed-service check was not reached |
| Installed Linux service | Five complete repetitions PASS with the unchanged `ff7016b9` installer in [run 39557237846](https://github.com/StannisMod/amnezia-client/actions/runs/39557237846): system resolver, strict switch, both app scopes, IPC reconnect, child crash recovery and exact OS-state restoration |
| Linux resolver stress | FAIL with the unchanged installer in [run 39558268939](https://github.com/StannisMod/amnezia-client/actions/runs/39558268939). A newly created TUN retained `~.` but lost its DNS server after reconnect; resolved reported no DNS scope and no route to host. The earlier isolated timeout is therefore not dismissed as an environment-only flake |
| Resolver correction | Source implemented at `ab782ce1`: D-Bus ownership/reconciliation of only the private TUN's DNS/domain/default-route state, change signals + periodic health checks, monitor shutdown before resolver rollback and fail-closed errors |
| Corrected Linux installed-package acceptance | PASS at `395c491f` in [run 39584835912](https://github.com/StannisMod/amnezia-client/actions/runs/39584835912): newly rebuilt RUN, clean installation, 20 resolver connect cycles, forced DNS-list reset recovery, cached FakeIP route identity, strict switch, both app scopes, IPC/crash recovery, exact OS-state restoration and package removal. Artifact: [routing-linux-verified-package](https://github.com/StannisMod/amnezia-client/actions/runs/39584835912/artifacts/12340530783). The earlier hybrid helper/service test at `ab782ce1` passed 100 cycles in run 39580790352 but was followed by an activation failure in another run; it is historical evidence, not the final stability gate |
| Windows installed MSI/EXE acceptance | PASS, including actual package uninstall, in [run 39584348717](https://github.com/StannisMod/amnezia-client/actions/runs/39584348717) and repeated PASS in [run 39584836050](https://github.com/StannisMod/amnezia-client/actions/runs/39584836050). Both reuse the verified `ff7016b9` installers. Reports cover DIRECT/VPN TCP/UDP, IPv6, system resolver, strict switch, both app scopes, IPC reconnect, child crash recovery and exact OS-state restoration. Earlier jobs failed at a separate SCM stop before uninstall; `60145bd9` exercises the package's own removal operations and asserts its service registration is gone. Overlapped raw pipe I/O fixes the acceptance client's deadlock |
| Core tests | Local Go 1.27.1 complete race suite and vet PASS after `18efe265`. Native Linux namespace acceptance PASS in [run 39583807024](https://github.com/StannisMod/amnezia-client/actions/runs/39583807024); native Windows acceptance PASS in [run 39583807047](https://github.com/StannisMod/amnezia-client/actions/runs/39583807047) |
| iOS device/runtime | NOT RUN; signed app/extension provisioning and a compatible device are required. Unsigned compilation is not device acceptance |

The `ab782ce1` matrix [run 39580790455](https://github.com/StannisMod/amnezia-client/actions/runs/39580790455)
confirmed Android APK builds (four ABIs) and Linux app/service/RUN. The later source
fix superseded that run before iOS/Windows completion; cancellation is not PASS.
The current full matrix is [run 39583806899](https://github.com/StannisMod/amnezia-client/actions/runs/39583806899).
Observe its actual result before marking the final source build gate PASS.
Focused helper/package tests do not replace final full-client builds.

An intermediate publication mistake at `df43f0b8` created an incomplete Git tree.
`ab782ce1` restores the full verified `61596aba` base tree and applies only the
intended eight changed/added files; comparison against `61596aba` has **zero
removed files**. Local source was retained, and no branch reset/force-push was
used. The failed diagnostic run at that incomplete intermediate commit never
reached resolver verification and is not acceptance evidence.

A further resolver stress repetition [run 39582872546](https://github.com/StannisMod/amnezia-client/actions/runs/39582872546)
failed during a later session activation after successfully recovering a forced DNS reset.
Do not treat the earlier 100-cycle PASS as proof of stable activation. `18efe265`
adds bounded startup waiting specifically for resolved's `NoSuchLink` while its
netlink event is still being processed; other bus/permission/configuration errors
remain immediate failures. Failure-event details are retained in test reports.
The freshly rebuilt `b099c757` RUN in [run 39583024531](https://github.com/StannisMod/amnezia-client/actions/runs/39583024531)
also failed a later activation after its 20 resolver cycles and app-scope probes.
Its successful compilation and Qt regressions are not package-runtime acceptance.
The startup-wait correction was added later at `18efe265`. The failed runs did not
retain the native error category, so `NoSuchLink` is a plausible startup race,
not a conclusively proven cause of those particular failures. The corrected
fresh package now passes the complete 20-cycle installed-service test. The
expanded five-by-20 diagnostic run [39585281916](https://github.com/StannisMod/amnezia-client/actions/runs/39585281916)
is still running at this checkpoint and is not marked PASS.
Full fresh Linux packaging is checked independently, including installation and
system-resolver stress; installer artifacts require a PASS report before acceptance.
Linux installer/test/removal commands are bounded, Python emits periodic stalled-thread
stacks, and focused native diagnostics retain only fixed allowlisted error categories;
raw syscall traces and fixture profiles/keys are never persisted as artifacts.

### Resumed desktop product fixes

- Linux exposes app split tunneling when the routed engine is enabled and
  provides an executable-file selector. Windows/Linux expose both app modes
  with that engine; legacy Windows retains its exclusion-only UI.
- Enabling domain routing no longer rejects desktop app scope or kill switch:
  the existing native/service integration implements those combinations.
- Restoring a routed Windows backup retains include mode. Linux restores the
  application mode/list/enabled state through the existing controller signals.
- UI models notify property bindings on repository-driven changes, including
  backup restoration, without double-emitting explicit setter notifications.
- A nonempty desktop app scope that requires the routed engine is rejected
  before starting an incompatible legacy transport; its saved rules are not
  silently ignored. Empty app lists retain existing all-app behavior.
- Regression tests exercise independent include/exclude lists, restored scope,
  live-editor notifications and rejection of unsupported legacy app scope.
  Linux and Windows CI run the settings/application UI regression targets.

Still unaccepted: physical mobile devices, signed iOS packet-flow/egress and
memory limits, native network handover, always-on/lockdown combinations,
performance measurements, complete protocol regression and full GUI interaction.
Keep these requirements open; successful builds do not close them.

Historical checkpoints below preserve the evidence and failures that led to
the current implementation; later entries supersede earlier source status.


## Historical implementation checkpoints

2026-10-19. Branch: `feature/sing-box-routing`.
Verified base: `ddde43635e957ebf042d92787489da72d3394019` (`origin/dev`).
The original DNS-fix checkout was left intact; this work uses a separate
worktree. All four submodules were initialized at the base's pinned commits.
No repository AGENTS.md was present.

**The four-platform handoff is not complete. No installable feature client has
been produced. Android now has opt-in Qt/service/JNI source integration and a compiled unified
native payload. Device validation and full client acceptance are still pending.**

## Implemented source

- Pinned, unified Go module: sing-box v1.14.3 plus AWG v3.1.20260814, Go 1.27.1,
  `with_gvisor`, committed checksums, no upstream source patches.
- Versioned shared rules, strict domain/wildcard validation, IDN/case/trailing
  dot handling, suffix boundaries, deterministic precedence, inverse routing,
  disabled rules and callable legacy site conversion without cached-IP rules.
- Dedicated AWG TCP/UDP outbound and a mandatory native protected-socket
  contract; a separate protected DIRECT outbound; no fallback from VPN to DIRECT.
- Session compiler for one capture inbound, DNS hijacking, managed FakeIP,
  explicit DNS resolver detours, AWG parameters and disabled default logs.
- Native route installation is deliberately not attempted by this core.
- Four-platform client-baseline CI lanes using existing deploy entry points;
  Android uses hosted runners and all four ABIs. iOS has an opt-in unsigned
  compile path. Aggregation fails if a required lane fails/cancels/skips.
- Build reports distinguish baseline compilation, native feature integration,
  signing, installers and runtime tests. No automatic release publishing.

Architecture, source pins, runtime caveats and alternatives are in ADR-001.md.

## Executed verification

Go commands ran from `native/routing` with Go 1.27.1 on Linux x86_64.

| Check | Status | Evidence / limits |
| --- | --- | --- |
| `go mod verify` | PASS | All module checksums verified |
| `go vet -tags with_gvisor ./...` | PASS | Static Go checks |
| `go test -mod=readonly -tags with_gvisor -race -count=3 ./...` | PASS | AWG, engine and rule packages; three repetitions; no race findings |
| AWG inner IPv4 and IPv6 | PASS | Real local TCP and UDP echoes through encrypted AWG peers, non-default J/S/H parameters |
| Two domains sharing one real IP | PASS, host flow test | Real sing-box FakeIP and routed connections reach different observers; test DIRECT factory maps observer to loopback |
| Remote AWG loss | PASS, host flow test | Fresh VPN-selected flow fails; DIRECT observer sees no additional connection |
| Managed DNS | PASS, host flow test | Actual local UDP DNS server; A/CNAME and AAAA responses; caching and explicit clear; captured A query gets FakeIP without reaching upstream |
| Rules/migration | PASS | Wildcard/apex boundaries, normalized duplicate conflicts, longest suffix/prefix, IDN, inverse mode, disabled-rule persistence, cached-IP omission |
| Android arm64 Go packages | PASS | `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...` |
| Android armv7/386/amd64 Go packages | PASS | Same command with corresponding GOARCH and GOARM=7 for arm |
| iOS arm64 Go packages | PASS | `GOOS=ios GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...`; **no c-archive/framework or extension linking** |
| Windows amd64 Go packages | PASS | Same command for GOOS=windows; **no DLL/service linking** |
| macOS arm64 Go packages | PASS | `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...`; core package regression only |
| CI source lint | PASS | actionlint 1.7.7; YAML parsed; deployment shell passes `bash -n` |
| Manifest smoke check | PASS | Compile PASS does not imply runtime PASS; iOS signing stays BLOCKED |

The local host has no `/dev/net/tun` and forbids netlink sockets. The engine
flow tests supply a test-only loopback interface inventory. They do not test
physical/Internet egress, native capture, policy routes or interface monitoring.
The initial real-engine startup reproduced the netlink restriction; tests were
then explicitly scoped to flow routing, rather than marked native PASS.

## Full-client baseline attempts

| Platform | Command / host | Status | Blocker |
| --- | --- | --- | --- |
| Linux installer | `deploy/build.sh --generator Ninja --installer all` | BLOCKED | Existing Qt 6.10.1 available, but Qt Installer Framework absent |
| Linux app/service compile | `deploy/build.sh --generator Ninja` with separate build directory | BLOCKED | Conan 2.28.0 cannot resolve `go/1.23.12` required by libagw/1.0.8; configured Amnezia Artifactory remote is rejected as an invalid Conan remote |
| Android ARM64 APK | `deploy/build.sh -t android --abi arm64-v8a --apk` | BLOCKED | Qt Android toolchain, Android SDK/NDK absent; script fails on missing Qt Android toolchain file |
| iOS app + extension | `deploy/build.sh -t ios` | BLOCKED | Linux host has no Xcode generator, Apple SDK or Qt iOS; signing identities and app/extension profiles also unavailable |
| Windows app + service + installers | `deploy/build.bat --installer all` | NOT RUN | No Windows host, MSVC, WiX or Windows Qt in the executor |

CI baseline lanes are source-added and linted, not evidence of executed remote
builds. CI must be observed at the pushed commit. Existing Android-only self-hosted
runner availability was not established; the new lanes do not require it.
No APK, IPA, RUN, EXE or MSI from this feature was generated. Old DNS-fix
installers found elsewhere were not reused or presented as feature artifacts.

## Functional acceptance by platform

| Requirement | Android | iOS | Linux | Windows |
| --- | --- | --- | --- | --- |
| Native capture/TUN integration | SOURCE INTEGRATED; FD test PASS | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Native DIRECT/protection and AWG bootstrap | SOURCE INTEGRATED; device NOT RUN | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| DNS/FakeIP under OS capture | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Qt persisted rule editor/profile migration installed | SOURCE INTEGRATED; client build pending | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Reconnect, crash, shutdown, native fail-closed | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Per-app rules and conflict precedence | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Installer/device/extension smoke test | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Existing protocol regression | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

## Remaining engineering and external assets

Android integration now overlays the routing bridge into the existing AWG
Go payload, preserving old JNI entry points. ARM64 c-shared compilation with
NDK 27.0.12077973 passed; exported old/routed JNI and 16 KB ELF alignment were
checked. The same native FD adapter passed raw DNS/FakeIP and failed-start/
shutdown cleanup tests with race detection. Qt migration contract tests passed.
The next gate is the complete APK compile, payload inspection and device test.

The actual service-process runtime/load behavior still requires device proof. The existing AWG Go dependency
is linked through CMake; blindly adding another Go shared library is not valid.
Then replace the AWG packet reader only for the experimental routed session,
wire persisted rules from Qt, and run a real ARM64 APK against a controlled AWG
endpoint. Retain old backends for unaffected sessions/protocols.

iOS must reconcile the new module with the existing AWG/XRay Go payload and
connect the same engine to the existing Network Extension packet flow. Linux
and Windows need their existing service/TUN/driver/DNS lifecycle integration.
None of these is completed by the package-only cross-compiles.

External prerequisites for complete verification: working source/prebuilt Conan
dependency access; Android toolchains and device/emulator; Windows build/test
runner; macOS/Xcode runner and Apple device. Signed iOS installation additionally
requires matching app and extension identities, provisioning and entitlements.
A controlled unchanged AWG server and two independent egress observers are
needed for actual network-path acceptance. Do not put credentials in logs or
committed fixtures.

Other open work: endpoint roaming/bind refresh, native network handover,
lockdown/always-on policy, loopback/LAN/resolver regression, DNS TTL expiry and
reconnect restoration, QUIC, DoH/DoT fallback, CNAME edge cases, 100-cycle
resource checks, performance/memory measurements and complete distributable
license notices. Keep feature activation unavailable until host integration is
implemented and verified. No server or dev-branch changes were made.

## Android implementation details in this checkpoint

- `Awg.startVpn` selects the routed path only when `sing_box_routing` is present.
  It retains the legacy AWG/WG JNI functions and does not retry them after a
  routed-start failure. One app VpnService builder supplies the capture FD.
- The Go host owns that FD, refuses a second reader and always releases it and
  its JNI global callback on a failed start or normal stop. Native socket
  callbacks use `VpnService.protect` before connect/send; counters and handshake
  status are returned without exposing the private UAPI.
- Qt adds a persisted, default-off experimental AWG switch on Android. Existing
  site lists/modes serialize as schema v1 names, without cached DNS IPs. New
  routed domain entries do not perform `QHostInfo` startup resolution.
- The capture includes IPv4 and all IPv6, including the FakeIP ULA range.
  An AWG profile with no IPv6 path cannot fall back to DIRECT for VPN flows.
- Conan pins AWG Android source commit 5c16489e2cd9ed3a0a7a27c7445bba5238132f86,
  adds the core to the same `libwg-go.so`, and uses a Go-1.27.1-specific checked
  CLOCK_BOOTTIME patch to retain suspend-aware mobile timers.
- Full Kotlin/client/payload CI verification has been added. Full client builds
  at the preceding core-only commit passed for Linux and all four Android ABIs;
  those older APKs do not contain the new Android integration.


## Update: native mobile integration and editable rules (2026-10-19)

This update supersedes the earlier source/CI statements above where they differ.
The four-platform mission remains incomplete. No native VPN device acceptance
has been executed, and desktop routing integration remains open.

- Android: actual Kotlin protocol modules and unified JNI payload compiled on
  all four ABI CI lanes at `fe9a5a8a`. Full APK packaging reached the modified
  Conan recipe and exposed a dangling-symlink copy failure. The recipe now
  preserves symlinks; the corrected APK build still needs to pass.
- iOS: CI run 39253601451 built the arm64 AWG/XRay/routing c-archive, verified
  old/new C symbols and typechecked the Swift public PacketTunnelFlow adapter.
  The complete unsigned app/extension build was still running when recorded.
  This is compilation evidence, not entitlement/device/underlay proof.
- The iOS implementation uses public readPackets/writePackets, one packet
  reader and the existing Go archive. Network changes replace the Go session
  while retaining that reader and OS capture. includeAllNetworks is rejected;
  provider-owned BSD sockets require native egress verification on a device.
- The new Qt editor persists per-rule domain/suffix/CIDR, DIRECT/VPN and
  enabled/disabled state plus the default route. First activation migrates the
  active legacy list without resolved IPs. Existing settings backups include
  the new Conf keys. Legacy lists and other protocols are retained.
- Both mobile hosts now choose a private persistent FakeIP database. Only
  domain/FakeIP identities persist; real DNS response caches are fresh on a
  transport restart. File permissions are restricted to the application user.
- Local tests passed: real gVisor packet-FD and public packet-flow managed DNS;
  three restart cycles preserving IPv4/IPv6 FakeIP identity without address
  reassignment; C ABI failed start, packet DNS/FakeIP, restart, stats and stop
  lifetime; Go race tests; Qt canonical-rule migration/validation contract.
  QML parsing passed. Full Qt controller persistence/backup tests are added
  to the existing UI regression target and need CI execution.

Open acceptance remains: complete feature APK and unsigned iOS app builds,
Android emulator/device and iOS device network-path verification, stable native
network handover/100-cycle cleanup, performance, all protocol regressions,
Linux/Windows service capture and native DIRECT integration, installable desktop
artifacts containing routing, and signed iOS distribution. Ordinary host builds
or pre-feature installers must not be reported as feature acceptance.

## Actual APK acceptance and UDP regression (2026-10-19)

The complete build run `39255117799` at `34ce45ea` passed all four Android
ABIs, unsigned iOS app/extension, Linux and Windows build lanes, and existing
Qt persistence/UI tests. Those results supersede earlier pending build entries.
Desktop artifacts from this run still use the legacy routing backend.

An actual packaged x86_64 APK now runs under its production `AwgService` in a
disposable Android 35 emulator. Run `39294909757` verified FakeIP DNS, DIRECT
TCP/UDP and AWG TCP against independent host/netstack observers sharing one
real IP. AWG UDP **FAILED**. No Android acceptance pass is claimed.

The failure reproduced in a new host test exercising sing-box's UDP router,
which the earlier connected-UDP transport test did not cover. Binding an
unconnected AWG UDP flow to the configured tunnel address, rather than an
explicit wildcard address, fixes the pinned userspace stack's `no route to
host` error. Both IPv4/IPv6 unconnected UDP and the FakeIP UDP routing
regression pass locally with race detection. A newly linked APK must still
pass the emulator matrix before this is marked fixed on Android.

The emulator workflow uses a test-only instrumentation APK and temporary
signing identity. It re-signs a disposable copy of the feature APK and verifies
that every native payload byte is preserved; release artifacts are untouched.
Private fixture keys and fixture-bearing test APKs are never uploaded.

## Linux service integration checkpoint (native runtime verification pending)

- The persisted experimental editor and routing profile now reach the existing
  desktop service IPC on Linux. The service launches and owns a private Go
  child, packaged beside it through CMake and built from the pinned module.
  Credentials cross stdin, not command lines or configuration files.
- The child owns one TUN and gVisor reader. A dedicated capture table and one
  inverse-mark rule per family capture ordinary flows after the local table.
  Protected DIRECT/AWG sockets skip only this capture rule and continue through
  native OS policy; no default gateway is forced. Occupied reserved state or
  overlapping mark policies cause startup rejection, never replacement.
- Startup, shutdown and partial-start rollback track exact owned routes/rules.
  A helper crash leaves a lower-priority blackhole until explicit recovery by
  the service. Recovery recognizes exact owned entries and refuses foreign
  policy state; it never flushes a shared table.
- systemd-resolved receives DNS on the new VPN link and is reverted on stop.
  The local `127.0.0.53` stub is never routed to a router. If selected as the
  engine resolver, its numeric upstream is snapshotted before VPN DNS changes.
- Per-app desktop routing and the existing OS/strict kill switch are explicitly
  gated rather than silently bypassed. Their integration is still unfinished.
- Local checks: native helper compilation; AWG profile/parameter conversion and
  rejection tests with race detection; Go vet; Qt domain contract; syntax check
  of the new C++ child owner; workflow/Python checks. These are not native VPN
  acceptance. A real network-namespace CI checks capture, independent TCP/UDP
  observers, native policy routing, IPv6, CNAME, loopback, AWG/helper loss,
  inverse mode, FakeIP persistence, 100 reconnects and exact route restoration.
  Installed Qt-service, systemd-resolved, installer and network handover tests
  remain separate requirements.

The test-only peer is excluded from Android/iOS package cross-compilation;
otherwise `go build ./...` would try linking an unrelated host executable with
CGO disabled. Android CI retries transient failures downloading the same pinned
NDK version; it does not substitute a different NDK or payload.

Runtime follow-up: the first Linux namespace run (`39297636360`) caught a
startup route-encoding error: the netlink API requires an explicit default
destination even when its family is supplied. That source correction is
pending a rerun; no Linux native PASS is claimed.

The emulator lane now builds the current unified JNI payload with the same
reproducible script as the full-client lane. It can apply that payload to the
packaged test APK only after checking its production Android host sources are
unchanged from that APK's source SHA. The report identifies both SHAs and the
native checksum. This incremental APK is emulator-only evidence, not a newly
compiled Qt client, installer, release artifact or physical-device acceptance.

## Windows source integration and mobile runtime follow-up

The desktop service owner now has a platform-neutral name and is wired into
the existing Windows service IPC as well as Linux. The Windows helper uses the
repository's pinned Wintun 0.14.1 dependency and the same routing/AWG module.
It chooses each destination's native route via GetBestRoute2 across native
interfaces, compares prefix length plus route/interface metrics, excludes the
capture adapter, and applies IP_UNICAST_IF/IPV6_UNICAST_IF before TCP connect
or each UDP send. UDP syscall fast paths are deliberately hidden so that they
cannot bypass that protection. Loopback retains its native local path.

The helper owns adapter DNS/addresses/routes and a dynamic WFP DNS guard;
specific native routes receive more-specific capture routes so literal VPN
destinations cannot escape merely through a pre-existing LAN route. The cache
directory has an explicit SYSTEM/Administrators ACL and an exclusive file
lock. Existing per-app routing and OS kill-switch combinations remain gated.
Windows helper-crash fail-closed policy, installed-service/installer smoke,
handover and real-device behavior are still unfinished. Source integration
and a successful Go cross-build do not establish Windows runtime acceptance.

A dedicated Windows CI now exercises the actual route API/ABI, Wintun capture,
system DNS, DIRECT/AWG TCP/UDP observers, IPv6, loopback, inverse policy and
100 reconnects with native route/DNS restoration. Results are pending.

Android incremental run `39298167660` confirms the UDP correction under the
actual APK's AwgService: shared-IP domain separation, TCP/UDP on both paths,
suffix/exact precedence, CNAME, IPv6 TCP/UDP, system resolver and loopback all
passed. A later inverse-mode check after peer/session restart timed out, so
the full Android result remains **FAIL**. Fresh host tests now cover both
default policies and pass; reconnect/peer recovery remains under investigation.


## 2026-10-20: full builds passed; first-packet race reproduced and corrected

Full CI run `39301511270`, source `6767d516`, passed all four Android ABI APKs,
unsigned iOS application/extension, Linux installer, Windows EXE/MSI, and core
race tests on Linux, Windows and macOS. This confirms desktop service packaging
and compilation; it does not establish native runtime acceptance.

Native runs `39301511519` (Linux), `39301511380` (Windows), and `39300503667`
(Android) still failed. A local regression using real UDP DNS through AWG,
rather than a hosts-only DNS backend, reproduced the shared startup failure.
AWG snapshots S4 before entering its first blocking TUN read; applying UAPI
after device construction could leave that read using the old padding offset.
The first data packet was then rejected as an unknown message. Parallel A/AAAA
queries and peer/session restarts made the packet loss visible.

The shared flow-device constructor now suppresses eager EventUp and completes
that initial read without consuming a packet after UAPI application. Its next
iteration reloads the configured padding before traffic starts. The disposable
peer uses the same constructor. First-flight DNS burst and real upstream DNS /
DIRECT / AWG restart regressions pass repeatedly; the complete local Go race
suite passes. Native reruns remain required before upgrading any acceptance
status. The Android lane now uses the latest successful full APK as its host.

Linux capture also matches a clear socket-exemption bit directly. Inverting a
rule would invert its entire selector, including iif lo, and could capture
native input lookups. Explicit recovery recognizes both the new owned rule and
the previous owned form. The actual namespace test remains the deciding check.

Native Linux run `39371691161` progressed through real TUN TCP/UDP, IPv6,
CNAME, native policy routing, loopback, AWG outage, inverse mode, FakeIP
persistence and 100 reconnects after the startup fix. It then failed explicit
recovery after the forced helper crash. The pinned netlink decoder restores
Mark/Mask but never MarkSet; recovery must identify the exact owned mask/value
instead of relying on that flag, and explicitly encode MarkSet on deletion.
The same correction makes preflight detect foreign mark policies. A new native
conflict-rejection scenario verifies those rules remain untouched. The entire
Linux acceptance result remains FAIL until recovery/restoration also passes.

## Native follow-up: Windows pass and Android resource cleanup

Windows native run `39371691099` at `afa7f399` **PASSED** actual Wintun capture,
independent DIRECT/AWG TCP/UDP, IPv6, managed/system DNS, CNAME/suffix rules,
loopback, AWG outage without DIRECT fallback, inverse mode, persisted FakeIP,
100 reconnects, and exact native route/DNS restoration. This is disposable-host
helper acceptance; installed Qt service, installer smoke, handover, helper-crash
policy and the gated OS kill-switch/per-app combinations remain unverified.

Android run `39371691061` passed all traffic scenarios and 100 reconnects,
including inverse mode and persisted FakeIP, but the complete result **FAILED**.
The expected failed-start test had an IPC ordering race: DISCONNECTED precedes
ERROR, so the test must consume both before starting the replacement session.
It also measured descriptor growth from 95 to 196 in the same service process
(threads 31 to 34, RSS 154724 to 165324 KiB). A new local repeated-capture test
reproduced one leaked eventfd per reconnect in the pinned gVisor fdbased endpoint.

Descriptor capture now uses the existing packet-flow channel endpoint with a
single Go pollable-file reader and nonblocking native writes. It closes that
reader and the capture descriptor explicitly, avoids dependency-internal access
or patches, and passes the local eventfd regression and complete Go race suite.
Native emulator resource verification and throughput measurements remain
required; packet-copy overhead must not be inferred from compilation success.

Linux run `39372104523` again completed traffic and 100 reconnects. Recovery
removed its rules, then failed deleting dumped default blackhole routes because
the pinned encoder also requires an explicit destination for deletion. Recovery
now restores the correct family-specific /0 destination before deleting the
exact owned route. The next native run must prove complete restoration.

## Android preflight and final native-test refinements

Android run `39372709101` at `1cdf51cf` confirmed the descriptor fix: **93 -> 93**
in the same service PID over 100 reconnects (threads 28 -> 34, RSS 155008 ->
167040 KiB). Traffic, inverse mode and FakeIP persistence passed again. The
complete result remains **FAIL**: DNS timed out on the valid connection after
an intentionally invalid profile. Unsupported routing schema was still being
rejected only after Builder.establish had created a transient Android VPN.

The host now calls shared native schema/routing validation before establishing
or replacing the OS interface; Start repeats the same validation defensively.
The new JNI method is part of the existing unified Go library. Tests verify
preflight rejects unsupported rules without creating capture/cache resources.
Because production Kotlin changed, emulator CI now waits for this exact
source commit's successful full-client build instead of applying JNI to an
incompatible older APK. Failure diagnostics snapshot live routing before test
cleanup disconnects the VPN. Native recovery verification is still pending.

Linux run `39372709136` completed explicit recovery and removed owned capture
rules/blackholes, then failed its final native-route text comparison. The test
now waits for native IPv6 DAD/link-local initialization before taking the
baseline, records that baseline, and prints a precise restoration diff. Native
route restoration is not marked PASS until the revised run completes.

A real QUIC/TLS host test now transfers a segmented stream through AWG at MTU
1280, verifies its digest and covers inner IPv4 and IPv6. It passes locally
with race detection using the already-pinned QUIC dependency. This is flow
transport evidence; native application/TUN QUIC acceptance remains unrun.


## Owned AWG flow-stack shutdown and portable fixture binding

Linux native run `39373901624` at `2a46d327` **PASSED** the complete namespace
suite, including foreign-mark conflict rejection, traffic, IPv6, 100 reconnects,
helper-crash fail-closed behavior, explicit recovery, and exact native state
restoration after a settled IPv6 baseline.

The repeated full-core CI then exposed a close/send race in the pinned AWG
convenience netstack: it closed incomingPacket while a gVisor notifier could
still send a delayed TCP packet. The routing module now owns its small private
flow-TUN adapter using the same pinned public gVisor protocol/socket APIs. It
cancels producers, waits for admitted I/O, stops the stack and releases queued
views without closing a channel under a sender. AWG device/crypto code and its
wire protocol are unchanged; no dependency patch or second runtime is added.
An adversarial pending-output shutdown test and repeated TCP/UDP close tests
pass with race detection, as does the complete suite with CI's count=3.

The Windows core runner also rejected the fixture's fixed outer UDP port
51820 as reserved by the host. The disposable peer now binds an available
system-selected port, records it in its private generated profile, and retains
it across restart. Fixed inner observer ports remain inside the userspace AWG
stack. Native acceptance must rerun because the owned flow adapter changed.


## Native acceptance passed on the owned flow stack

At source `f7847c02`, Linux run `39375044711` and Windows run `39375044707`
report native_capture=PASS, reconnect_cycles=100 and os_state_restored=true.
Linux also proves the helper-crash blackhole and explicit recovery. These are
helper tests on disposable hosts; the Linux namespace deliberately uses
--no-system-dns and does not establish installed-service/systemd-resolved
acceptance. Windows installed Qt-service, installer smoke and helper-crash
fail-closed policy remain outside that pass.

Android run `39376118150` at CI-only source `d75d1850` **PASSED**. It used the
full x86_64 APK host built from `f7847c02`, with identical production Android
host sources and a freshly linked unified JNI payload. Both SHAs/checksums are
in its artifact. It verifies shared-IP domain identity, DIRECT/AWG TCP/UDP,
suffix/exact precedence, CNAME, inner IPv6, system DNS, loopback, AWG outage,
inverse mode, persisted FakeIP, 100 reconnects, and invalid-profile preflight
rejection followed by a successful valid start. The preflight case does not
claim every possible post-establish native-failure path was tested.

The same service PID (3624) stayed alive throughout: descriptors **93 -> 93**,
eventfds **5 -> 5**, and capture descriptors **0 -> 0** at disconnected
checkpoints. Threads were 31 -> 35; RSS was 157648 -> 168520 KiB. RSS is a
measurement, not a leak/performance acceptance threshold. Physical devices,
handover, always-on/lockdown and native application QUIC remain unrun.

The compatible APK job can pass before other platform jobs finish. Emulator CI
verifies that specific job, source SHA and host compatibility; the separate
full build gate still requires every platform. CI-only follow-ups leave the
in-progress full source build running.

Native acceptance reports/artifacts:

- [Linux run 39375044711](https://github.com/StannisMod/amnezia-client/actions/runs/39375044711), artifact `12243097357`.
- [Windows run 39375044707](https://github.com/StannisMod/amnezia-client/actions/runs/39375044707), artifact `12243108193`.
- [Android run 39376118150](https://github.com/StannisMod/amnezia-client/actions/runs/39376118150), artifact `12242654376`.

No dev merge, release publication or production-server change was performed.

## Final source build verification

[Full source matrix 39375044626](https://github.com/StannisMod/amnezia-client/actions/runs/39375044626)
completed successfully at `f7847c02895d5c3e356811b7d0d03e3927f42eeb`.
All four Android ABI APK jobs, Linux application/service/installer, Windows
application/service/EXE/MSI installers, unsigned iOS application/PacketTunnel
extension, three desktop race-test jobs (count=3), eight package cross-compiles
and the aggregate build gate passed. Windows artifact: `12245266425`; unsigned
iOS artifact: `12244427896`; Linux artifact: `12243950123`.

Later commits only adjust CI/reporting; shipping source remains the verified
`f7847c02` source. Android native acceptance uses the compatible full APK host
from that same matrix. A build PASS is not installed-client acceptance, signed
iOS device acceptance or release approval. The feature remains experimental
and off by default, with the limitations listed at the top of this report.

## Windows helper-crash guard — pending native acceptance

The private helper now installs a separate non-dynamic WFP sublayer before
capture. Its default outbound IPv4/IPv6 block survives helper termination;
only the helper executable, captured interface LUID, native loopback and DHCP
are permitted. Graceful shutdown removes the exact owned filters after closing
the engine. An unclean session refuses restart until explicit recovery removes
its private keys, transactionally, without flushing other firewall policies.
This protection lasts until explicit recovery or BFE restart; it is not a
boot-time filter and does not yet integrate the existing strict kill switch.

The Windows native suite now forcibly kills the helper, checks that Wintun is
gone while native outbound TCP connect is denied by WFP (WSAEACCES), rejects a stale
restart without losing protection, recovers, and reconnects. This new suite
must pass before helper-crash protection is marked accepted.

## Desktop application scope — pending native acceptance

Desktop profiles now translate application include/exclude lists into process
path rules before destination rules, with anchored literal-path matching and
case-insensitive Windows identity. Linux symlinks are normalized to the kernel
executable path when present. Shared DNS is captured first; unidentifiable
non-DNS process owners are rejected. A process selected for VPN still follows
its domain DIRECT/VPN rules; an app outside the selected scope uses DIRECT.
Mobile application scope remains owned by its native platform service.

Actual pinned sing-box parser/matcher tests cover include/exclude precedence,
unknown owner rejection, DNS capture, path metacharacters and Windows casing.
The local complete race suite passes count=3. Linux and Windows native suites
now compare separate Python/Go executables against the same FakeIP destination
for both TCP and UDP. Those new native cases have not passed yet.

Windows run `39395467839` passed traffic and 100 reconnects, then failed the
first crash assertion. Unconnected UDP sendto may return before WFP drops a
packet, so that API return value is not packet-delivery evidence. The revised
suite verifies surviving WFP objects directly and checks synchronous TCP
connect denial, with native reachability checks before capture/after recovery.
No crash protection PASS is claimed from the failed run.

A later reporting-only matrix `39380227075` exposed a macOS fixture timeout
in TestEngineRealDNSAndPeerRestart. The prior verified source matrix remains
historical evidence; repeatability on macOS is still under investigation.

## Strict-switch service integration and installed-package acceptance — pending

The Qt service now owns narrow firewall exceptions for the protected routing
helper and the captured interface. Windows uses a separate owned filter group,
IPv4/IPv6 app identity and capture LUID; Linux validates and owns a two-rule
iptables/ip6tables chain for its reserved socket mark and capture interface.
The existing strict policy remains blocked between sessions; live toggles
reapply the owned exceptions. Cleanup restores the strict state before the
native child releases capture. Domain DIRECT rules and application scope are
still evaluated by the shared engine, rather than legacy IP-filter rules.

Unexpected service-pipe EOF, signals and runtime statistics failure now close
the engine but retain native fail-closed policy. Explicit stop/recovery releases
that owned policy. Both native suites check pipe-loss recovery as well as hard
termination. This guard is not boot/BFE-restart protection.

The first application-scope native runs rejected unknown owners. Desktop hosts
with no Go network monitor had not seeded sing-box's interface inventory, and
newly captured source addresses were absent from that pre-TUN snapshot. The
host now initializes its native inventory and reports its assigned capture
addresses through the platform API. Unknown ownership remains rejected.

Full CI now builds a small client of the real QtRO switch API, installs the
Linux RUN package and both Windows MSI/EXE packages, then tests the installed
service's actual child, system resolver (including systemd-resolved), live
strict-switch changes, application scope, IPC reconnect, helper crash/recovery
and OS-state restoration. These are new tests, not yet PASS evidence.

Local Go race suites pass count=3; the DNS/restart regression passes count=30.
The real QtRO probe compiles/links, and the edited Linux C++ service/firewall
units pass syntax checking. Native Windows ABI/guard-lifetime checks passed in
run 39396896294 before that run stopped at the application-scope rejection.
Correctness TCP deadlines now allow the existing AWG/TCP retry timers on loaded
CI hosts; the independent first-flight A/AAAA UDP burst still has a 2s deadline.


## Native application scope and crash acceptance passed; QUIC probes added

At `6d111d66`, Linux `39449842500`, Windows `39449842545` and Android
`39449842506` passed their complete native suites. The desktop suites include
separate executable owners, include/exclude TCP/UDP, retained protection after
service-pipe loss and forced helper termination, explicit recovery, 100
reconnects and native-state restoration. Windows additionally checks native
WFP ABI/object lifetime and TCP WSAEACCES after termination. Installed Qt service
and strict-switch acceptance remain pending in full matrix `39449842520`.

The new disposable `traffic-probe` verifies TLS 1.3 against an ephemeral fixture
certificate and a 64 KiB stream digest using ordinary native UDP sockets.
Linux/Windows namespace/Wintun and Android actual-service suites now request
DIRECT IPv4 and VPN IPv4/IPv6 QUIC probes. Android packages the probe executable
in the throwaway instrumentation APK and executes it in a separate process
with the instrumented app UID; the production APK and its single Go runtime
are unchanged. Local race tests verify both observer labels and rejection of
a different CA. Native QUIC results are still pending and are not claimed PASS.
