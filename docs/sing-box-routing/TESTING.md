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
go test -mod=readonly -tags with_gvisor -race -count=3 ./...
go vet -tags with_gvisor ./...
cd ../..
```

Full-client entry points are `deploy/build.sh --generator Ninja --installer all`
on Linux, `deploy/build.bat --installer all` on Windows,
`deploy/build.sh -t android --abi arm64-v8a --apk` for Android, and
`deploy/build.sh -t ios` on a configured macOS/Xcode host. Setup and unsigned iOS
options are defined by `sing-box-routing-ci.yml`; those commands alone do not
install Qt, SDKs, Conan dependencies, installer tools or signing identities.

The following workflows can be rerun on the feature branch through Actions:

| Workflow file | What a successful result establishes |
| --- | --- |
| `sing-box-routing-ci.yml` | All client compilation/packaging lanes, core race tests, cross-compilation and embedded installed-service gates |
| `routing-linux-package.yml` | Fresh Linux package installation, actual Qt service, resolver cycles, restoration and removal |
| `routing-installed-linux.yml` | Current helper with the explicitly identified older Qt installer; diagnostic evidence only |
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
