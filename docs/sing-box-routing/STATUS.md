# Implementation checkpoint — incomplete

## Continuation — 2026-10-22

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
