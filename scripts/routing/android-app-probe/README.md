# Two application UIDs through the actual VPN APK

`run_android_acceptance.py` builds and signs this source twice as independent
packages `org.amnezia.routingprobe.a` and `.b`. Each self-targeted instrumentation
process owns its own kernel sockets. No shared UID is declared. The existing
throwaway-emulator guard applies before installation or starting either probe.

The loopback-only JSON control ports 19091 and 19092 expose readiness, opening
and retaining a named TCP stream, verified echo over that same socket, a fresh
UDP flow, ordinary TXT DNS, and shutdown. They carry synthetic test data only.
Both probes resolve the identical system DNS name before TCP/UDP. The ordinary
TXT requests also use the same name, so stale or shared resolver caches cannot
stand in for independent application DNS contexts.

Use the normal acceptance arguments with `--app-policy-only` to focus on the
new service IPC path. This mode explicitly reports that full acceptance was not
run. Full acceptance includes the same scenario. The local peer must be started
with `--persistent --native-dns-port 1053`; its native and encrypted DNS paths
return different TXT markers. The test checks both observer counters as well.

A starts VPN-only and B follows a DIRECT site rule. After the service confirms
the inverted UID policy, new TCP/UDP and TXT queries must invert paths while
both original TCP sockets still exchange bytes and retain their local ports.
The test also requires identical FakeIP identity, different real Android UIDs,
exactly four total observer accepts, and unchanged service process and TUN.

These APKs belong only on disposable rooted emulators. The driver force-stops
both packages and waits for their instrumentation processes during cleanup.

For package lifecycle investigation, add `--package-lifecycle` together with
`--app-policy-only`. After the initial policy switch the emulator driver
first updates B in place (same UID, same VPN session and A's TCP), then
uninstalls and reinstalls B, starts its probe again, and records Android's VPN
network state on both sides. The scenario requires a different UID, an automatic
VPN session restart, and B's new TCP and TXT DNS through VPN. Existing TCP may
reset in this exceptional case; ordinary policy edits above must still retain it. A reused UID is rejected as insufficient evidence. Finally a package update
after manual VPN disconnect must leave VPN disconnected. This focused mode is
reported as `NOT_RUN_PACKAGE_LIFECYCLE_ONLY`; it does not establish full client
acceptance. Package mutation is allowed only after the existing rooted-emulator
guards, and the flag is required before honoring a reinstall checkpoint.

Add `--private-dns-opportunistic` to `--app-policy-only` to exercise Android's
active opportunistic Private DNS. Start the disposable peer with
`--native-dns-port 1053 --native-dot-port 8853`. The driver redirects only the
rooted guest's QEMU DNS-proxy TCP/853 to the local peer, enables opportunistic
Private DNS and removes its exact redirect and setting during cleanup. It does
not change the computer's DNS or firewall. The test requires Android to report
active Private DNS before VPN startup, then uses the production network DNS
snapshot for DIRECT resolution. The TLS observer counts only synthetic
`*.app-policy.test` queries, so Android's own resolver validation cannot satisfy
the application-transport assertion. Both original TCP sockets must survive
the policy switch as in the ordinary case. The existing API29 regression jobs
combine this mode with package lifecycle coverage.

`run_android_work_profile.py` accepts the same APK/fixture/work arguments and
runs the existing per-app/lifecycle scenario in a newly created managed profile.
It requires a rooted disposable emulator and removes its profile in `finally`.
An additional copy of probe A in the personal profile keeps an original literal-IP
TCP connection and opens a new one while the work VPN and its policies change.
Both personal connections must stay DIRECT; work A/B must follow their own
policies, and the same package's full UID difference must equal `userId * 100000`.
The report says `NOT_RUN_WORK_PROFILE_ONLY`; this is focused coverage, not a
100-cycle or arbitrary cross-profile system-DNS-cache claim. API29 AWG/WG jobs
run this after their personal-profile scenario without adding matrix jobs.

This scenario covers opportunistic network DNS and these applications' A/UDP
TXT requests. It does not prove strict Private DNS certificate handling,
work-profile behavior, or isolation of arbitrary system TXT/SRV cache entries.


`run_android_acceptance.py --private-dns-policy-only` checks the chosen strict
Private DNS compatibility contract without installing a trusted resolver CA.
A configured strict provider must reject startup with effective domain rules
and reject enabling those rules live for an otherwise always-VPN app. A second
session starts with Private DNS off, retains a real encrypted-tunnel TCP stream,
enables strict DNS, and requires the new-flow gate and nonfatal service notice.
The old stream must still echo; a fresh captured TCP must reject promptly.
After the host manually disables strict DNS, DNS recovery must reopen fresh TCP
without changing the TUN session or the original socket. The driver only changes
settings in a rooted disposable emulator and clears them in `finally`. API29
AWG/WG jobs run this focused check alongside the existing suites; it does not
claim support for encrypted system DNS together with effective domain rules.


Xray IPv6 regression: `build_xray_fixture.py` builds a native test peer using
only the checked Android libxray recipe archive and its exact SHA256. The CLI
uses that archive's go.mod/go.sum and Xray fork replacement, not a separately
chosen upstream version; it records source and binary provenance.
`xray_ipv6_fixture.py --xray PATH --work DIR` runs on an isolated rooted Docker
container or disposable GitHub-hosted runner. It starts VLESS/TLS and real
kernel IPv4, global IPv6, ULA and NAT64 TCP/UDP origins. The pinned fork blocks
private/documentation destinations by default; the fixture authorizes only its
four owned addresses and two test ports. It changes no system trust store.
The fixture removes only the loopback addresses it added when stopped.

`run_android_acceptance.py --xray-ipv6-only` uses the actual XrayService and
packaged libxray/tun2socks. Each successful TCP/UDP response must also increment
the VLESS ingress count for that exact address: a native IPv6 bypass cannot
satisfy this test. It separately waits for IPv4 and IPv6 kernel capture, then
checks that explicit IPv4 site inclusion keeps unselected IPv6 traffic direct.
The existing AWG jobs on API29 and API35 run this after their AWG checks; no
extra matrix jobs are introduced. This proves client capture and local IPv6
egress through VLESS/TLS, not IPv6 auto-deployment of a real remote Docker host
or support on Windows/macOS/iOS.
