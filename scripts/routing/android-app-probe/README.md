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

This scenario covers opportunistic network DNS and these applications' A/UDP
TXT requests. It does not prove strict Private DNS certificate handling,
work-profile behavior, or isolation of arbitrary system TXT/SRV cache entries.
