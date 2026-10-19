# Implementation checkpoint — incomplete

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
