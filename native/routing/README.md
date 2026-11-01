# Shared routing core — experimental source milestone

The shared sing-box routing core has source integration in Android's existing
VpnService/JNI payload, iOS's existing Network Extension, and the Linux/Windows
privileged service. It remains an experimental opt-in feature.

Current build, native fixture and installed-package evidence, unresolved DNS
stress failures and device/signing gaps are tracked in
[`../../docs/sing-box-routing/STATUS.md`](../../docs/sing-box-routing/STATUS.md).
Do not infer physical-device or Internet-egress acceptance from compilation.

## Build and test

IP-literal flows (including clients using their own DoH resolver) are sniffed
for visible HTTP Host, TLS SNI and QUIC ClientHello before domain rules, with a
300 ms sniff budget. This does not decrypt HTTPS. Existing FakeIP identities
take precedence over sniffed names; application scope and DNS interception
retain their existing priority. When no domain is available, IP rules and the
configured default still apply. ECH may hide the original destination name.

`engine.RoutingConfig` compiles common policy independently of the VPN adapter.
`SessionConfig` selects a typed `vpn` adapter (`awg` or `wireguard`), with explicit
TCP/UDP capabilities and validation before capture. Legacy top-level `awg` JSON
remains readable; mixing legacy and explicit transport settings is rejected.
Routing policy, managed DNS, sniffing, application scope and cache identity are
shared. Other protocols still require adapters; raw sing-box outbounds are not
accepted.

`engine.Runtime` owns start/cancellation/close and transport-neutral statistics.
`mobile.Session` owns native descriptor release, including failed starts. Linux
and Windows retain their platform-specific route/DNS cleanup and crash recovery;
the refactor does not substitute a second OS route manager. Android now shares
the routed lifecycle in `Wireguard`, with `Awg` specializing profile parsing.
iOS selects the same explicit adapter through its existing packet-flow owner.

Standard WireGuard uses the existing AWG device in compatibility mode without
extensions, as the legacy client already does. Its schema excludes AWG parameters
and accepts a scalar keepalive in 0..65535. Obfuscated WG profiles must use the
AWG adapter. `wireguard/interop_test.go` verifies IPv4/IPv6 TCP/UDP against an
independent upstream wireguard-go peer pinned only for tests; no second VPN
runtime or reference peer is bundled into the client.

Diagnostics count Direct/VPN selections, managed-DNS/sniffed/unavailable domain
identities and default decisions, plus the last matching configured rule and
network type. They report routing choices, not successful delivery. Data stays
in memory and contains no observed destination name/address. Desktop helper
status includes `routing`; iOS runtime status and Android's
`RoutingBackend.diagnostics(handle)` expose the same JSON. A user-facing
connection inspector is not included.

Validation includes the same shared-IP/FakeIP/real-DNS/sniffing and TCP/UDP cases
for both adapters, native FD/packet-flow cleanup, controlled socket/capture
startup failures and reconnect loops. Linux namespace CI covers AWG and WG on
Ubuntu 22.04/24.04, including crash recovery and OS state restoration. Physical
mobile devices and native platform packages still require their CI/runtime
checks; local loopback tests do not establish those results.

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

- `rules`: version 2 portable schema (reads version 1), canonicalization, validation, deterministic rule
  order, legacy site-list conversion and sing-box route-rule compilation.
- `awg`: a dedicated `amneziawg` outbound using the unmodified AWG v3 device
  and its in-memory TCP/UDP stack. It requires a native underlay socket factory.
  The `keepalive` session field preserves AWG's string syntax (`"25"`, `"25-35"`,
  or `"0"` to disable); older numeric JSON values are also accepted. Validation
  uses the pinned AWG range parser before the value reaches UAPI.
- `engine`: shared registries, a protected DIRECT outbound, and a session
  compiler combining capture, managed DNS/FakeIP, rules and typed VPN adapters. A native host
  still has to supply its platform interface and implement TUN/route ownership.

The session compiler disables automatic OS route installation, because those
routes must be integrated with Amnezia's existing native service. Starting it
without that native integration is not a working split-tunnel client.

## Rule contract implemented here

```json
{
  "version": 2,
  "default": "vpn",
  "rules": [
    {"kind": "suffix", "value": "*.ru", "action": "direct"},
    {"kind": "domain", "value": "example.com", "action": "vpn", "network": "tcp", "ports": "80,443,8000-8100"},
    {"kind": "domain", "value": "blocked.example", "action": "block", "disabled": false},
    {"kind": "cidr", "value": "192.168.0.0/16", "action": "direct"}
  ]
}
```

Exact domains win over suffixes; longer suffixes win over shorter suffixes;
then longest CIDR prefix; then default. Within equal specificity, saved list order
is authoritative. Duplicate enabled canonical conditions (destination, ports and
network) are rejected; overlapping but different conditions retain list order.
Port lists and inclusive ranges form a union, then AND with the destination and
network. Empty/absent `ports` means all destination ports; empty/absent `network`
means both TCP and UDP. Values outside 1..65535 and unknown network types fail
validation, including in disabled rules. `block` is a reject/drop action before
any outbound opens; as the default it appends an unconditional reject, rather
than selecting a nonexistent block outbound. DNS interception and application
scope still run before destination policy. Existing diagnostic outbound counters
do not count rejected flows; the static policy checker does report Block.

Version 1 policies remain readable (including native sessions' null/absent empty
rules list), but cannot carry Block or port/network conditions. The editor and
exports write version 2. Unknown versions and fields are rejected instead of
being silently dropped on import or native session parsing.

### Portability is required

The split-tunneling page always offers routing JSON import/export, even when the
experimental engine is disabled or a connection prevents editing. Export remains
available during a connection; import, like editing, is disabled then. Import
validates the complete document before replacing any saved policy; a malformed,
oversized (>1 MiB), unsupported or duplicate policy leaves existing settings
unchanged. Policies are limited to 4096 rules and 1024 characters of port input
per rule; the editor also refuses policies whose canonical export exceeds 1 MiB.
Imported settings do not toggle routing/split-tunneling switches or change VPN
profiles, DNS servers, application lists or credentials. Those belong to the
existing application backup; this portable file contains the common destination
policy only, so it has no platform-specific paths or tunnel secrets.

Export preserves the default, all conditions, disabled rules and tie-breaking
list order. Canonical hostname/CIDR/port spelling can change, without changing
policy. Any future routing-policy feature must be represented in this versioned
contract and its import/export round-trip coverage before it is added to the UI.
The old legacy site-list import/export remains a separate format.

The policy checker evaluates saved rules against the exact hostname and/or known
IP, destination port and TCP/UDP selection supplied by the user. It reports the
original editor rule number or default; port 53 reports managed DNS interception
before destination rules. It does not perform DNS queries or claim
to observe active browser metadata. Application exclusions, disabled routing,
unsaved edits or hidden hostnames can produce a different live outcome. Qt and
the pinned sing-box matcher consume `rules/testdata/portable-cases.json` to check
their contract, including import migration, rejection and egress decisions.

`*.example.org` includes its apex and descendants at DNS label
boundaries. Case, a trailing ASCII dot, and Unicode IDNs are canonicalized.
Disabled rules are persisted and validated but do not match. Inverse mode uses
`"default": "direct"` with explicit `"action": "vpn"` rules.

Desktop application include/exclude scope is evaluated by executable path
before domain rules; unknown process owners are rejected and DNS stays captured.
Native platform services own mobile app capture scope.
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
5. Stop platform DNS-state monitors before restoring owned resolver settings.
   Close the engine/TUN before releasing owned capture and crash policies.
   Handle startup rollback, kill switches and lock-down constraints in the host.

Default logs are disabled, including the AWG device logger. UAPI rejection
returns generic errors, without keys, configuration text or hostnames.

## Licensing

sing-box is GPL-3.0-or-later with an additional naming/association notice; its
upstream notice is reproduced in `licenses/sing-box-LICENSE`. AWG's MIT notice
is in `licenses/amneziawg-go-LICENSE`. These are the direct engine/transport
notices, **not a complete distributable's transitive license bundle**. Before
shipping, collect notices for the selected module graph (including both gVisor
modules), the existing app dependencies and any embedded runtime/toolchain
components, and supply corresponding source where required. Experimental CI
artifacts are produced; completing the distributable license bundle remains a
separate delivery requirement.
