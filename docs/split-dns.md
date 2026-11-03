# Split DNS

Split DNS selects a real DNS server and its DIRECT or VPN path by the queried
domain, within one AWG or WireGuard routed session. Enable domain routing, then
open **DNS servers**, enable **Different DNS for domains**, and save the policies.
Changes apply on the next connection; disconnect before editing DNS settings.

**DNS by site route** implements “where the site goes, its DNS goes”:

- Domain rules selecting DIRECT use the selected direct DNS policy.
- Domain rules selecting VPN use the selected VPN DNS policy.
- Unmatched names use the DNS policy corresponding to the routing default.
- Explicit DNS exceptions take priority over site routing.

Without that switch, explicit DNS exceptions and the default DNS policy decide
DNS independently of traffic routing. An explicit DNS exception does not change
the site's traffic route. Application rules and IP/CIDR rules do not determine
DNS: the originating application or destination IP may be unavailable when a
system resolver asks its question. This also means an application-scope override
can change traffic routing without changing the domain's DNS policy.

## Matching and DNS records

Within explicit DNS exceptions, exact names precede suffixes; longer suffixes
precede shorter suffixes. A suffix includes its apex and descendants at DNS label
boundaries: `*.corp.example` includes `corp.example` but not `evilcorp.example`.
Case and one trailing ASCII dot are ignored. Configuration accepts IDNs and
normalizes them to ASCII. Disabled exceptions remain stored and validated;
conflicting enabled canonical duplicates are rejected. Site-rule ordering is
unchanged. Automatically discovered corporate domains sit between explicit DNS
exceptions and site-route DNS selection.

Captured A/AAAA questions receive FakeIP addresses. The real upstream is queried
when a connection needs the real address. Both DIRECT and VPN outbounds perform
that lookup through the same domain DNS rules, skipping the synthetic resolver.
Other query types, including TXT/SRV and service labels containing underscores,
go directly to the selected real resolver. A CNAME response does not create a
second independent policy decision. Malformed multi-question messages retain
the underlying DNS router's format-error handling.

Real-answer caches are isolated by transport identity in the pinned sing-box
client. Real answers are not persisted between sessions. Reconnection, policy
changes and network changes create a fresh runtime/cache. The private persistent
FakeIP store retains only address/name identity, so application-cached FakeIPs
recover the original name and resolve it using the new policy. Existing live
connections close on reconnection. Real addresses cached by an external
application cannot retrospectively acquire a domain identity.

## DNS transports and failure behavior

Policies support UDP, TCP, DoT (`tls`) and DoH (`https`). Default ports are 53,
53, 853 and 443; the default DoH path is `/dns-query`. TLS certificate validation
stays enabled. A numeric encrypted upstream can specify `server_name` for TLS.
A named upstream requires a separate numeric bootstrap server, reached through
the same DIRECT/VPN path and, when set, the same network interface. Bootstrap
resolves only the upstream's hostname; it never uses captured DNS or FakeIP.
VPN endpoint bootstrap remains a separate mechanism.

There is no automatic fallback to another policy or DNS server. NXDOMAIN is an
answer, not a request to try another resolver. The UDP transport may retry a
truncated response over TCP to the **same server and port on the same path**.
If the VPN fails, VPN-selected real DNS requests fail; they do not use DIRECT.
An already synthesized FakeIP is not evidence that its upstream is reachable.
DIRECT remains subject to existing platform traffic-blocking constraints. This
feature does not relax Android lockdown restrictions or bypass a kill switch.

Only queries entering the managed resolver are controlled. Applications using
their own DoH/DoT can bypass split DNS. Visible hostname sniffing for a later
connection does not control the application's preceding encrypted DNS request.

## DNS from the network

Linux supports **Use DNS from the current network** and **Preserve corporate DNS
domains from the network**. The privileged helper reads systemd-resolved's
per-link server/domain inventory before installing VPN DNS and excludes its own
interface and unusable/stub addresses. Search expansion remains with the OS;
search domains also become DNS suffix policies for fully expanded questions.
Original network interfaces' resolver settings are not rewritten.

Network-source policies use one selected link's first numeric server with an
explicit UDP/TCP transport. Leave the interface empty only when exactly one
eligible DNS default-route interface exists; otherwise select the interface.
Corporate domains use that link's first numeric server over UDP. Automatic
discovery covers conventional per-link DNS; it does not reproduce the OS's
encrypted-DNS transport configuration or all systemd-resolved features. Configure
DoT/DoH explicitly when those transport requirements matter. Multiple interfaces
claiming the same corporate suffix are rejected rather than queried in parallel.
There is no implicit secondary-server failover.

These sockets are both exempted from capture and bound to the selected network
interface. Ordinary DIRECT sockets retain destination-specific native routing.
A monitored inventory change stops the prepared session with capture protection
retained. Reconnect reads a new snapshot; the existing network-change machinery
can trigger reconnection, while a DNS-only change may require user reconnection.
Shutdown stops DNS monitoring before reverting the owned VPN link.

Automatic network DNS discovery is currently Linux-only. Windows, Android and
iOS accept the same explicit policies and exceptions. A network-source policy
restored on those platforms is rejected, never silently replaced with public
DNS. Ordinary macOS/macOS NE do not gain routed-core availability from this
change. Native SDK/device validation remains separate from Go cross-compilation.

## Stored settings and native schema

The existing secure settings repository stores `Conf/splitDnsV1` and a separate
`Conf/splitDnsEnabled` flag in the same global scope as existing DNS settings.
Switching split DNS off retains the editor configuration. App backups include
these keys; connection exports do not acquire the user's local DNS policies.
Profiles without active split DNS keep their existing resolver/path behavior;
`dns2` is not silently introduced as a new routed fallback.

Qt passes active policies as `sing_box_dns`. Desktop profile conversion, Android
and the Apple bridge supply the common session's `dns` field. Unknown schema
versions, missing policies, ambiguous bindings and invalid resolver paths fail
validation. Unsupported transports cannot fall back to a legacy VPN backend
while split DNS is enabled. Disabling domain routing first requires disabling
split DNS. A fresh install has an empty custom routing list and a VPN default;
saved user rules are preserved.

Example of the native `dns` field:

```json
{
  "version": 1,
  "default": "vpn",
  "follow_routing": true,
  "direct": "lan",
  "vpn": "vpn",
  "policies": {
    "lan": {"name": "Corporate DNS", "transport": "udp", "server": "192.168.10.53", "path": "direct"},
    "vpn": {"name": "VPN DNS", "transport": "udp", "server": "1.1.1.1", "path": "vpn"}
  },
  "rules": [{"kind": "suffix", "value": "corp.example", "policy": "lan"}]
}
```

Linux network-source policies use `"source":"network"`, `"server":""`,
`"path":"direct"` and optionally `"interface":"eth0"`. Corporate-domain
discovery uses `"preserve_network_domains":true`. Prepared network rules and
the inventory fingerprint are runtime data, not saved user configuration.

## Verification

Run the common core checks with:

```sh
cd native/routing
go test -mod=readonly -tags with_gvisor -race ./...
```

`TestSplitDNSSimultaneousPolicies` uses two independently observed DNS servers
in one runtime, one on protected DIRECT sockets and one inside an encrypted AWG
peer. It checks exact/suffix/default precedence, case, trailing dots, suffix
boundaries, service-label TXT, A/AAAA, NXDOMAIN, FakeIP followed by real
connections, and failure isolation in both directions. A separate named-upstream
test verifies explicit bootstrap without recursive/application-name queries.

`scripts/routing/run_split_dns_acceptance.py` additionally runs the actual Linux
TUN helper and systemd-resolved with separate corporate/VPN observer namespaces.
It verifies simultaneous server/path selection, OS search/routing domains,
network-source interface binding, reconnect with an application-cached FakeIP
and changed policy, network DNS invalidation and resolver restoration. The
`split-dns-system-resolver` CI job runs it for AWG and WireGuard in privileged
containers with **no external network**. Its report contains only synthetic test
domains; generated private profiles/keys remain inside the discarded container.

Qt tests cover settings round trips, invalid-rule rejection, retained disabled
configuration and fresh-install routing defaults. The DNS page also has an
actual QML editor/save round-trip test. Linux checks do not constitute Windows,
Android or Apple device/SDK acceptance.
