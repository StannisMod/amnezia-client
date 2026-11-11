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
uninstalls and reinstalls B, starts its probe again, and records Android's VPN
network state on both sides. The scenario requires a different UID, unchanged
A's original TCP, and B's new TCP and TXT DNS through VPN without replacing the
core. A reused UID is rejected as insufficient evidence. This focused mode is
reported as `NOT_RUN_PACKAGE_LIFECYCLE_ONLY`; it does not establish full client
acceptance. Package mutation is allowed only after the existing rooted-emulator
guards, and the flag is required before honoring a reinstall checkpoint.
