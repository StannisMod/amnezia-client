# DNS follows site routing

AWG and WireGuard routed sessions automatically resolve each site's name on its
selected path. There is no separate split-DNS switch, per-path DNS editor,
per-domain DNS exception list or corporate-DNS override.

- DIRECT sites use the DNS configuration of the original network, without VPN.
- VPN sites use the effective DNS already selected by Amnezia's existing settings
  and server/profile configuration, through VPN. The existing **Use AmneziaDNS**
  setting and ordinary DNS fields remain the only VPN-DNS configuration.
- Unmatched names follow the routing default. Exact/suffix matching is the same
  as for site traffic; case and one trailing dot are ignored.
- A failed resolver fails its lookup; it never retries on the opposite path.
  A/AAAA FakeIP responses alone do not prove a real upstream lookup succeeded.

The policy is derived on every connection, after the ordinary DNS selection.
Changing AmneziaDNS, the ordinary DNS address, the selected server or the site
routes therefore applies on reconnect without updating a second DNS setting.
Old `Conf/splitDnsV1` and `Conf/splitDnsEnabled` data, including restored backups,
are ignored. They cannot disable automatic DNS routing or add DNS exceptions.
Switching to an unsupported/legacy protocol is not blocked by an obsolete flag.

When all domain names use VPN, native network-DNS discovery is unnecessary.
DIRECT CIDR rules alone do not create a direct DNS policy: numeric addresses do
not need name resolution. Disabled domain rules do not affect DNS selection.
When any names use DIRECT, the platform snapshots the original DNS before
installing its own VPN DNS; missing or ambiguous network DNS fails preparation.
Corporate DNS routing domains are not imported as higher-priority rules: they
cannot cause a VPN site's DNS query to escape through a physical interface.

## Native network DNS

The original network's DNS settings are read automatically; there is no new
server, interface, transport or TLS setting in the UI.

- Linux: systemd-resolved per-link DNSEx and effective global/link DoT settings.
  Numeric address, port and authentication name are retained. Strict TLS checks
  certificates; opportunistic TLS stays encrypted without a plaintext fallback.
- Windows: native adapter/default-route DNS selection, original-interface socket
  binding and advertised system DoH auto-upgrades. NRPT domain overrides are not
  imported into the automatic site policy.
- Android: non-VPN LinkProperties and retained Network handles with protected,
  bound sockets. Strict and opportunistic Private DNS modes are retained.
- iOS: the public libresolv conventional DNS snapshot and underlying-interface
  sockets. Apple does not expose the complete scoped/corporate/managed encrypted
  DNS configuration through this adapter. DNS-only changes require reconnect.
  Ordinary macOS routed-core availability is unchanged.

Native snapshots cross session serialization; runtime policies are prepared
inside the core, preserving native opportunistic TLS without exposing an
insecure-TLS user option. Reconnect creates a fresh real-answer cache. Persistent
FakeIP data retains address/name identity only, and resolves again under the new
site route. Network DNS changes invalidate stale snapshots; owned VPN DNS state
is restored on shutdown without rewriting the original interface settings.

## Scope and verification

This behavior applies to AWG/WireGuard sessions using the routed core. It does
not add routed-core support to other protocols or platforms. The existing domain
routing switch still selects that backend; it is not a split-DNS switch.
Applications using their own DoH/DoT are outside the managed resolver. Existing
application-scope overrides and IP-only traffic cannot provide a reliable domain
identity for a preceding system DNS query; their attribution limits are unchanged.

The Qt contract tests exercise the actual policy builder and export its output
with `dns_policy_fixture`. The Linux TUN/systemd-resolved acceptance consumes
that output for both AWG and WireGuard, checks separate DIRECT/VPN DNS observers,
corporate domains that must not override VPN site rules, application-cached
FakeIP after site-route changes, network DNS refresh and restoration. A real DoT
observer with an untrusted certificate checks opportunistic success and strict
rejection after the production session JSON boundary. Qt page tests verify the
ordinary DNS editor and restored obsolete settings. All fixtures use synthetic
names and isolated networks, never a user's VPS.
