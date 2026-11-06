# TCP recovery dependency integration

2026-11-06. Feature: `feature/connection-stability`.

The RACK flight-accounting correction is now a normal versioned dependency,
not a patch applied at CI runtime or an experimental modfile. Normal root and
mobile builds use the replacements in their main `go.mod` files. The upstream
proposal remains open; this is a downstream-tested backport, not a claim of
completed upstream review.

| Main module/build | Original baseline retained | Pinned downstream commit |
| --- | --- | --- |
| Routing core, Linux/Windows helper, Android unified payload | `1f7806d17489` (2023) | `8155b9498bd45bf332199ed5167cbfc6963ebd67` |
| Apple unified AWG/XRay/routing payload | `89a5d21be8f0` (2026) | `9cf7fba2d57c7fe7251d3b491d2cb513b8a2cc60` |

Both commits are in [StannisMod/gvisor](https://github.com/StannisMod/gvisor), on
separate dependency branches. The fork's `master` is unchanged. Keep the commits
reachable; normal builds are pinned to their pseudo-versions and `go.sum`
checksums, not moving branch names. The separate `github.com/sagernet/gvisor`
module used by sing-box capture is not replaced by this fork.

## Build contract

`native/routing/internal/builddeps/lock.json` is shared by the build verifier,
embedded provenance and package checks. It identifies both scopes, fork commits,
module/go.mod sums and hashes of the three changed TCP files, the fork marker and
the downstream notice. A root replacement is not assumed to be inherited by the
Android/Apple main modules: both overlay entry points declare their own correct
replacement through the normal module templates.

The normal engine imports the fork-only `gvisor.dev/gvisor/pkg/amnezia` marker.
An unpatched upstream module cannot compile the ordinary engine. Startup also
checks the linked source identity; build/package checks require the actual full
fork identity, not just a marker or a claimed source graph.

- Desktop CMake verifies the resolved graph before compiling and reads module
  metadata from the resulting helper afterward. `--build-info` reads runtime
  provenance without opening a tunnel, cache, resolver or protected socket.
- Android's recipe and standalone build use the same verifier. APK verification
  extracts each actual `libwg-go.so`, reads its Go module metadata without
  executing it, checks the new JNI provenance entry point, and retains the
  existing single-runtime, symbols and 16 KiB alignment checks.
- Apple validates its main module before building. The recipe checks the real
  static archive's exported provenance entry point and the Go module metadata
  inside its Go object. Flat GNU/BSD and Apple universal (`lipo`) archives
  are supported; every architecture must pass. Invalid slice ranges, unsupported
  containers or missing metadata fail the build. The host C ABI test also calls
  the actual bridge's provenance API.
- Notice generation resolves and verifies the same graph, includes the fork's
  `NOTICE-AMNEZIA`, and embeds dependency provenance. Apple inventories also
  attest the checked input archive's SHA-256. Final package/installed-service
  checks reject old notices, wrong scopes, wrong revisions and old helpers.
- Android/Apple Conan recipe versions are `routing.3`, and source exports include
  the lock and checker. This prevents reuse of the previous `routing.2` payloads.

All source and artifact checks fail closed. There is no automatic fallback to
upstream when the fork cannot be downloaded, a checksum differs, a main module
selects another version, or a packaged payload lacks the locked identity.

## Mandatory acceptance

The deterministic `TestTCPTimeoutRecoveryDrainsThroughACKs` is no longer opt-in.
It executes in the ordinary Go test matrix. Apple runs it in its real parent
module with `amnezia_gvisor_2026`, which only adapts the test probe API for that
retained baseline. It does not select a recovery algorithm or change production
code.

The Linux product job also executes the real WSS/TCP preservation fixture in
private mount/network namespaces. Both AWG/WG, inner IPv4/IPv6 and download/upload
are checked across the 1/3/10/30-second outage series and following packet loss.
The resulting native acceptance status and dependency identities are recorded in
the build manifest; logs and header-only traces remain in the existing Linux
artifact without changing its ZIP root layout.

The SDK matrix remains the release build gate. The installed Linux/Windows
service checks inspect the real installed helper's `--build-info`. Android reads
the actual APK payload; Apple checks the actual archive and bridge. These checks
prove which dependency was packaged; they do not replace device/physical-network
acceptance or make application deadlines disappear.

## Race-only dependency copies

The existing upstream ARM64 CAS correction is still applied only to private
copies by `prepare_race.py`; no shared module cache is modified. The preparer first
verifies the normal pinned fork and copies its resolved source, preserving the
RACK correction and marker. Its temporary modfile uses
`with_gvisor,amnezia_race_dependency` for race tests. Those binaries identify as
race diagnostics when the dependency is local and cannot pass package checks.

Pristine-upstream negative controls use the separate explicit
`amnezia_dependency_repro` tag. They cannot claim fixed provenance. Ordinary
builds use neither diagnostic tag. There are no user-facing stability switches.

## Current evidence and limits

Local integration checks include the ordinary root module and real Linux helper,
Go race regression, private-CAS preparation, negative artifact/source checks,
the real Apple parent graph, its minimal TCP regression, actual bridge ABI and
actual static archive metadata. Hosted SDK/installer results must be assessed
on the final PR head; a local host bridge is not an iOS device test.

The TCP change and its remaining algorithmic limits are described in
[TCP-RECOVERY.md](TCP-RECOVERY.md). It does not alter the outer reconnect manager:
full runtime teardown still destroys established connections. Merge and release
publication require their own user instruction.
