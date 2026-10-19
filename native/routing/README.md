# Shared routing core — experimental source milestone

This module is **not yet linked into the Amnezia clients**. It is not an APK,
Network Extension, service replacement, or completed four-platform feature.
See `../../docs/sing-box-routing/STATUS.md` for the acceptance gaps.

## Build and test

Use Go **1.27.1**, with `GOTOOLCHAIN=local` and `GOTELEMETRY=off`:

```sh
cd native/routing
go mod verify
go test -mod=readonly -tags with_gvisor -race -count=3 ./...
go build -mod=readonly -tags with_gvisor ./...
```

`with_gvisor` is required for the compiled session's userspace capture stack.
AWG's own in-memory flow stack is a different module; both execute in the same
Go runtime in these tests. No sing-box source patch is used.

Package-only cross-compilation (does not link an Android/iOS native library):

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...
GOOS=ios GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...
```

Versions are locked in `go.mod`/`go.sum`. Primary source commits:

| Dependency | Version | Commit |
| --- | --- | --- |
| sing-box | v1.14.3 | 7054cac5124465ffdb145870d7c01885566711b1 |
| AWG | v3.1.20260814 | 1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1 |

## Packages

- `rules`: version 1 schema, canonicalization, validation, deterministic rule
  order, legacy site-list conversion and sing-box route-rule compilation.
- `awg`: a dedicated `amneziawg` outbound using the unmodified AWG v3 device
  and its in-memory TCP/UDP stack. It requires a native underlay socket factory.
- `engine`: shared registries, a protected DIRECT outbound, and a session
  compiler combining capture, managed DNS/FakeIP, rules and AWG. A native host
  still has to supply its platform interface and implement TUN/route ownership.

The session compiler disables automatic OS route installation, because those
routes must be integrated with Amnezia's existing native service. Starting it
without that native integration is not a working split-tunnel client.

## Rule contract implemented here

```json
{
  "version": 1,
  "default": "vpn",
  "rules": [
    {"kind": "suffix", "value": "*.ru", "action": "direct"},
    {"kind": "domain", "value": "example.com", "action": "vpn"},
    {"kind": "cidr", "value": "192.168.0.0/16", "action": "direct"}
  ]
}
```

Exact domains win over suffixes; longer suffixes win over shorter suffixes;
then longest CIDR prefix; then default. Conflicting duplicate canonical rules
are rejected. `*.example.org` includes its apex and descendants at DNS label
boundaries. Case, a trailing ASCII dot, and Unicode IDNs are canonicalized.
Disabled rules are persisted and validated but do not match. Inverse mode uses
`"default": "direct"` with explicit `"action": "vpn"` rules.

There is no application-rule implementation yet. Native per-app capture
exclusions and their precedence must be added before feature activation.
`rules.FromLegacy` is a callable conversion function, not an installed profile
migration. It uses domain keys and deliberately discards their cached DNS IPs;
the original profile and all unrelated settings must be retained by its caller.

## Network evidence and limits

`TestAWG31TCPUDP` exchanges real TCP and UDP over local encrypted AWG peers,
for inner IPv4 and IPv6, with non-default J/S/H obfuscation parameters.

`TestFakeIPSharedAddressEgress` uses the real sing-box DNS/FakeIP store and router,
plus two real TCP observers. Both names resolve to `10.77.0.2`; distinct FakeIPs
recover their original domain and select DIRECT versus AWG. Because the local
test environment has only loopback, the test's DIRECT factory maps its observer
to a loopback listener. AWG sends to a listener at `10.77.0.2` in the remote
userspace stack. This proves routing and transport composition; it is not a
physical/VPN Internet egress measurement. The test supplies a loopback interface
inventory because the executor forbids netlink. After shutting down the remote
AWG peer, a fresh VPN-selected connection fails without reaching DIRECT.

No OS TUN, UI, profile migration installation, Android lifecycle, Apple signing,
Windows service, Linux resolver restoration, real server interoperability,
QUIC, full DNS TTL/lifecycle suite or performance claim follows from those tests.

`TestManagedDNSUpstreamCNAMECacheAndFakeIP` exercises a real local UDP DNS
server through the protected DIRECT outbound: A/CNAME, AAAA, response caching,
explicit cache clear, and captured A-to-FakeIP without an upstream query.

## Host requirements before integration

1. One native packet capture owner, providing the platform's descriptor or packet
   flow to sing-box. Never pass the same descriptor to the old AWG reader.
2. Native protected `Underlay.DialContext` and `Underlay.ListenPacket` callbacks.
   Preserve destination-specific OS routing, local routes and policy tables.
   No unprotected fallback is installed by this module.
3. Numeric AWG endpoint from native underlay DNS bootstrap. The UDP endpoint is
   pinned per session; authenticated endpoint roaming and bind refresh are not
   implemented by this adapter. Restart the session when the underlay changes.
4. Managed DNS queries must enter through the capture tag. Internal real-domain
   resolution uses the explicit upstream detour and does not use reverse-IP
   identity guessing. A loopback resolver cannot be configured through AWG.
5. Always close the engine before restoring native routes and DNS. Handle native
   startup rollback, kill switches and lock-down constraints in the host.

Default logs are disabled, including the AWG device logger. UAPI rejection
returns generic errors, without keys, configuration text or hostnames.

## Licensing

sing-box is GPL-3.0-or-later with an additional naming/association notice; its
upstream notice is reproduced in `licenses/sing-box-LICENSE`. AWG's MIT notice
is in `licenses/amneziawg-go-LICENSE`. These are the direct engine/transport
notices, **not a complete distributable's transitive license bundle**. Before
shipping, collect notices for the selected module graph (including both gVisor
modules), the existing app dependencies and any embedded runtime/toolchain
components, and supply corresponding source where required. No distributable
binary is produced by this milestone.
