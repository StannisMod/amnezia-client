# Android application ownership experiment

    ANDROID_HOME=/path/to/sdk python3 scripts/routing/android-attribution/run.py --work /tmp/uid-experiment

Requires disposable Android emulator API 29+, JDK and SDK platform/build tools 36.
The driver installs three test-only packages, creates an app-scoped packet-sink
VPN, observes TCP/UDP and synthetic DNS requests, then removes all three packages.
It does not forward traffic or access external servers. Two applications have
independent UIDs; the active VPN owner queries getConnectionOwnerUid for their
original TUN tuples. Results include ordinary UDP DNS and Android's system resolver.

This proves basic UID attribution, not complete per-application DNS semantics.
The driver also opens TCP to the address returned by the system resolver and
requires each original FakeIP tuple to retain the requesting application's UID.
Android 10 CI observations returned `-1` for system-resolver DNS sockets while
direct DNS sockets, TCP and UDP retained correct application UIDs. The report
marks that platform limitation explicitly; it does not label DNS ownership as
supported merely because subsequent flow ownership passes. This distinction
is required for shared FakeIP lookup at connection time and does not solve
attribution of arbitrary system TXT/SRV queries without a subsequent flow.
Use `--shared-name --sequential` to observe cross-application system-cache reuse,
or `--shared-name` for concurrent requests. The synthetic DNS responder returns
different addresses for the two UIDs. Both child resolver calls must complete;
an unfinished call is a failure, not evidence about caching. Reports preserve
the observed request UIDs and returned addresses. Cache sharing is reported as
an observation rather than a required behavior on every Android release.
Add `--system-txt` to query the same TXT name through `DnsResolver.rawQuery`,
with UID-specific synthetic TXT responses and no subsequent connection for
that TXT result. API 35 sequential observations produced separate requests
and `uid-a`/`uid-b` answers even while A answers were shared from cache.
The CI shared-name scenarios include TXT for API 29 and 35; do not generalize
the API 35 result to Android 10 without inspecting that platform's report.
Resolver caching/coalescing, Private DNS, IPv6, network changes and API 29 need
additional cases before making general platform claims. Transition failures are
retried within a bounded interval; missing attribution remains an assertion failure.
The fixture uses unique synthetic names and does not capture real DNS payloads.
