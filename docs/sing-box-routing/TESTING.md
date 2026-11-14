# Experimental AWG domain routing: installation and verification

The feature is opt-in and requires the feature branch's client **and** native
service/extension. Use the artifacts from a completed build of the source you
intend to test. The current results and unresolved failures are in [STATUS.md](STATUS.md).
An unsigned iOS build cannot be installed as a working VPN without matching
application/extension provisioning and entitlements.

## Enable and revert

1. Export a backup using the existing client before replacing an installation.
   Test with a disposable profile first; keep exported credentials private.
2. Install the package for the host platform. Android CI APKs use development
   signing; an incompatible installed signature requires a separate test device
   or an explicit backup/uninstall/import process. Do not assume an in-place upgrade.
3. Import an existing AWG profile. No server change is required. Other protocols
   retain their existing backends and do not gain these domain guarantees.
4. Open **Split tunneling** and enable **Experimental AWG domain routing
   (supports *.ru)**. Enable split tunneling and choose the desired direction.
   Add a domain/suffix rule such as `*.ru`. Reconnect after editing the rules.
5. To revert, disconnect, disable the experimental checkbox and reconnect with
   the old backend. Review application-scope rules first: a scope unsupported
   by the old transport is rejected rather than silently ignored. Back up the
   new configuration before restoring an older backup or installing older code.

A suffix includes its root domain and matches DNS label boundaries. Rule
precedence is exact domain, longest suffix, longest CIDR, then default. Desktop
application scope is evaluated first; destination rules apply within the VPN
application scope. Changing list order does not override this precedence.

Managed DNS/FakeIP retains domain identity when names share a real address.
Applications using their own encrypted DNS or literal destination IPs cannot
be promised a domain-based decision; the IP/default policy applies instead.
VPN-assigned traffic must fail closed when AWG is unavailable. Android lockdown
is rejected for experimental domain routing; the client must report the policy
restriction rather than bypass it. Removing always-on policy may revoke VPN
consent, requiring authorization again.

## Reproduce automated checks

Use the toolchain versions pinned in `native/routing/go.mod`, the Conan recipes
and the checked-in workflows. Initialize repository submodules for full clients.
Build commands run from the repository root unless shown otherwise:

```sh
git submodule update --init --recursive
cd native/routing
go mod download
go mod verify
race_mod=$(python3 prepare_race.py --output "${TMPDIR:-/tmp}")
go test -mod=readonly -modfile="$race_mod" -tags with_gvisor,amnezia_race_dependency -race -count=3 ./...
go vet -tags with_gvisor ./...
cd ../..
```

The temporary modfile applies the upstream ARM64 race-only CAS fix to private
copies of the two pinned gVisor modules; production dependencies and module
caches are unchanged. See [PERFORMANCE.md](PERFORMANCE.md) for the regression
proof, measured ordinary/race costs and removal criteria.

Full-client entry points are `deploy/build.sh --generator Ninja --installer all`
on Linux, `deploy/build.bat --installer all` on Windows,
`deploy/build.sh -t android --abi arm64-v8a --apk` for Android, and
`deploy/build.sh -t ios` on a configured macOS/Xcode host. For iOS source builds,
set `AMNEZIA_CONAN_PREBUILTS=OFF` to omit the optional Amnezia binary mirror.
Setup and unsigned iOS options are defined by `sing-box-routing-ci.yml`; those
commands alone do not
install Qt, SDKs, Conan dependencies, installer tools or signing identities.

The following workflows can be rerun on the feature branch through Actions:

| Workflow file | What a successful result establishes |
| --- | --- |
| `sing-box-routing-ci.yml` | All client compilation/packaging lanes, core race tests, cross-compilation and embedded installed-service gates |
| `routing-linux-package.yml` | Fresh Linux package installation, actual Qt service, resolver cycles, restoration and removal |
| `routing-installed-linux.yml` | Repeat acceptance of the current verified Linux package, including installer checksum and production-source compatibility |
| `routing-linux-acceptance.yml` | Native namespace capture, observer egress, handover/outage tests, reconnects and recovery |
| `routing-windows-acceptance.yml` | Wintun/WFP, native egress, crash recovery and reconnects on a disposable Windows runner |
| `routing-installed-windows.yml` | Explicitly identified MSI/EXE installation and installed Qt service acceptance |
| `routing-android-package.yml` | Independent x86_64 APK build using the same pins/deploy script; no full-matrix claim |
| `routing-android-acceptance.yml` | Compatible real APK/VpnService on a disposable rooted emulator, including policy and reconnect checks |
| `routing-performance.yml` | Measured Linux data-path comparison with an explicitly identified installed legacy AWG binary |

Read each JSON report and source provenance, including both APK-host and native
source SHAs for incremental Android tests. Do not treat an earlier compatible
artifact as a newly rebuilt package. A failed/skipped/cancelled required job
does not satisfy the full gate. Failed jobs may still upload partial reports.

## Acceptance boundaries

Native tests require isolated hosts with administrative privileges, TUN/adapter
support, native network APIs and controlled observers. The Linux namespace
suite disables system DNS deliberately; installed-service tests cover
`systemd-resolved` separately. Do not run these scripts on a personal host:
they modify routes, firewall policy, adapters and VPN settings for their tests.

Physical Android Wi-Fi/cellular handover, suspend/resume, real iOS packet flow
and extension memory limits, physical network behavior, full GUI interaction
and unaffected protocol regressions remain separate acceptance work. Emulator,
namespace, core-flow and unsigned compilation results must retain their scope.
CI performance ratios describe the measured host/data path, not battery life or
performance parity across platforms.

Do not remove global firewall policy or flush routes to recover a failed test.
The private desktop helper's `--recover` operation recognizes only its owned
state, requires no live capture interface, and must be invoked through the
authorized service/test lifecycle. A surviving fail-closed policy is expected
after an unclean helper exit until explicit recovery.

Pinned routing dependency notices are shipped under `native/routing/licenses`
and referenced by [THIRD_PARTY_LICENSES.md](../../THIRD_PARTY_LICENSES.md).
The feature remains off by default until the four-platform acceptance criteria
are satisfied. Build artifacts do not constitute a public release.

Installed Linux CI can opt into `--ci-rescue` on disposable root runners. Its independently armed watchdog uses existing owned-state recovery operations after 420 seconds or a failed test. A triggered rescue is failure evidence, even if it restores runner connectivity; inspect the associated `.rescue.json`.

Installed Linux workflows now use `run_linux_service_container.py` with a privileged disposable Ubuntu 22.04 systemd container, its own bridge/PID/cgroup namespaces, system D-Bus and real systemd-resolved. The checkout and Qt toolchain are mounted read-only; the host network, system D-Bus and Docker socket are not exposed. JSON and service/resolver journal diagnostics are copied out even on failure, then the container is removed from outside its network namespace. This retains the production service and resolver integration checks while keeping the CI control connection outside the VPN.

For source-only Apple dependency builds, set `AMNEZIA_CONAN_PREBUILTS=OFF` when calling `deploy/build.sh`. This skips registration of the optional Amnezia binary mirror on a fresh Conan home and uses the exported local recipes plus the normal Conan sources. Existing Conan homes may already have that remote configured; use a clean Conan home for the same CI behavior.

### Domain endpoint recovery

`client/tests/endpoints` covers parsing, multi-answer attempts, real local IPC
acknowledgements and cancellation, plus a controlled UDP DNS server. The latter
checks that only matching questions/transaction IDs supply addresses, malformed
compression cannot hang the parser, and cancellation/timeouts revoke the socket
exception before completion. Android and portable Swift tests cover answer
reordering, newly published IPs and a finite recovery budget.

The Linux installed-service acceptance also runs
`scripts/routing/endpoint_migration_acceptance.py` with
`routing-endpoint-probe` (built alongside `routing-service-probe`). A disposable
network namespace hosts DNS and two UDP front doors to one real AWG peer. It
changes the A record and drops the old path without changing keys, waits for the
production session watchdog to reconnect through actual service IPC, and proves
VPN traffic works again with strict KillSwitch both off and on. It checks that
unrelated native traffic stays blocked during strict DNS bootstrap and that an
ordinary DNS socket remains blocked after the temporary exception is removed.
This does not replace Android/iOS device handover or macOS PF/WFP acceptance.

### Native IPv6 source/scoped-route probe

`scripts/routing/run_native_ipv6_scope.py` uses `cmd/native-ipv6-peer` to put two
independent TCP/UDP origins behind two owned TUNs. The sending sockets use the OS
TCP stack. It changes the unscoped destination route A→B→A while retaining both
old sockets, checks the new TCP/UDP path and exact server accept counts, then
removes the owned routes and closes both interfaces. It changes no default
route, DNS or firewall setting.

macOS uses interface-scoped host routes. XNU's
[`in6_selectroute`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6_src.c)
selects an interface using an established socket's source address; this probe
must verify that behavior on each supported native runner before relying on it
in the OpenVPN route manager. It is wired into the existing macOS core-test
lanes and requires both the explicit `AMNEZIA_NATIVE_IPV6_LAB=owned-runner`
opt-in and a GitHub Actions runner. Linux calibration requires
`AMNEZIA_NATIVE_IPV6_LAB=isolated-container`, root inside an empty network
namespace, and uses source-policy rules instead. Linux results and Darwin
cross-compilation do not prove macOS runtime behavior, production OpenVPN
integration, or physical network handover.

Desktop endpoint bootstrap queries only the peer hostname through the privileged
service's private UDP socket, using public resolvers 1.1.1.1 and 8.8.8.8 on
alternating attempts. Linux/PF exceptions are restricted to its owned source port,
root UID, resolver IPv4 and UDP/53; WFP already permits the service image. The
saved hostname and keys are retained. This bypasses system DNS caches and tunnel
DNS, but private/split-horizon names and networks blocking both public UDP DNS
resolvers are not supported by this bootstrap path. Truncated DNS replies fail
closed; there is no TCP fallback. Destination-routing DNS is separate.

### IPv4-only OpenVPN servers

The installed Linux suite also runs `legacy-full`, `legacy-export`,
`legacy-include` and `legacy-exclude` using configurations emitted by the actual
Qt configurator. The server has no IPv6 pool, while an independent native path
can reach GUA, ULA and NAT64 origins. Selected IPv6 must be rejected, DIRECT
exceptions must still carry TCP/UDP, and two original IPv4 TCP sockets must
survive. The old configuration fails this test by reaching the native origin.

`block-ipv6` needs IPv6 capture, as shown in the
[OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual/).
The managed blocking fallback supplies a local IPv6 address when no explicit
one exists, installs the selected routes, and uses `setenv opt disable-dco`
because DCO bypasses userspace ICMP rejection. Its separate marker prevents an
exported blocking profile from being mistaken for authenticated IPv6 support.
After support is confirmed, regeneration removes only this managed fallback;
explicit administrator addresses and blocks remain intact.

The UDP witness enables Linux `IPV6_RECVERR` to observe the ICMPv6 rejection.
Ordinary UDP applications may ignore that soft error; this test does not claim
that every application's UDP receive call fails immediately.

`legacy-api` checks the same IPv4-only case with an API-supplied profile.
Provider-owned IPv4 redirect and subnet directives are retained while IPv6
capture is enforced. Capability-learning tests cover Native, SelfHostedUser,
SelfHostedAdmin, PremiumV2, FreeV3 and ExternalPremium records, preserving their
keys, credentials and API metadata. The observation emits a separate UI
notification, so it does not trigger the local proxy's ordinary configuration
restart handler. It applies to the next connection; an authoritative provider
profile refresh can replace the cached observation. This test does not claim
that the current blocked session gains IPv6 without reconnecting.

The installed Linux suite also forces an IPv4-only server while keeping the
Qt-generated `full`, `include` and `exclude` profiles' cached IPv6 capability.
`AMNEZIA_OPENVPN_STALE_CAPABILITY=1` selects this case in the existing TLS lab.
An interface-bound native connection proves each GUA/ULA/NAT64 origin is live;
selected route lookups must point to the actual tunnel, DIRECT TCP/UDP must
still work, and two original IPv4 TCP sockets must survive. Selected sockets
may time out in this stale-capability case: this is a capture/fail-closed
regression, not proof of fast rejection or successful IPv6 service. The strict
ICMP/fast-rejection assertions for ordinary `legacy-*` profiles remain intact.

### Android OpenVPN3 configuration compatibility

`ConnectionTest::openVpnTunBuilderIpv6Compatibility` runs in the ordinary Qt
suite. Android local profile generation removes only the owned OpenVPN2
fallback `ifconfig-ipv6` line: shipped OpenVPN3 rejects that client-side option
even with `setenv opt`. The block marker, `block-ipv6`, routes, credentials and
explicit administrator configuration are retained. Desktop OpenVPN2 profiles
and exports retain their capture address.

To check the real JNI library from a normal APK on an owned emulator, first
generate profiles with the compiled Qt test, then run:

```sh
QT_QPA_PLATFORM=offscreen AMNEZIA_OPENVPN_TUN_BUILDER_FIXTURE=/tmp/openvpn-tun-builder-policies.json \
  deploy/build/client/tests/test_connection openVpnIpv6ProfileAndExport openVpnTunBuilderIpv6Compatibility
AMNEZIA_ANDROID_NATIVE_CONFIG_PROBE=owned-emulator \
  python3 scripts/routing/run_android_openvpn_config_probe.py \
  --sdk "$ANDROID_HOME" --apk /path/to/normal-x86_64.apk \
  --policies /tmp/openvpn-tun-builder-policies.json --report /tmp/openvpn3-startup.json
```

This extracts the unchanged APK's JNI libraries and compiles the repository's
SWIG wrappers plus a separate probe. It neither installs nor modifies the APK.
`eval_config` alone is insufficient: the probe initializes native connection
options and refuses the socket before transport. A structural invalid control
must fail. The optional `--tls-fixture` mode accepts only the fixed local
emulator gateway/port, records native TUN callbacks after a fixture TLS
handshake, and returns no TUN descriptor. Neither mode proves actual Android
TUN routing or packet forwarding.

The local IPv4-only server probe showed that OpenVPN3 drops IPv6 route callbacks
without a server-assigned IPv6 address and asks the adapter to block the whole
family. Selective IPv6 DIRECT exceptions for this case still need implementation
and real Android packet acceptance. Apple adapters also require separate
validation; the Android adaptation is deliberately not enabled for them yet.

`ProtocolConfigIpv6Test` exercises the actual common Android configuration
builder: full capture includes GUA, ULA and NAT64, excluding an IPv4 endpoint
preserves IPv6 capture, and an IPv4-only inclusion list does not capture IPv6.
Full `::/0` is represented by `::/1` and `8000::/1`, rather than narrowed to
`2000::/3`. The local JVM Android stub selects the pre-API33 exclusion compiler;
these unit checks do not substitute for real API33+ route acceptance. Both
existing Android package workflows run `:protocolApi:testDebugUnitTest` beside
the existing `:utils:testDebugUnitTest`, without another job.
