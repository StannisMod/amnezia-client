# Android application ownership experiment

    ANDROID_HOME=/path/to/sdk python3 scripts/routing/android-attribution/run.py --work /tmp/uid-experiment

Requires disposable Android emulator API 29+, JDK and SDK platform/build tools 36.
The driver installs three test-only packages, creates an app-scoped packet-sink
VPN, observes TCP/UDP and synthetic DNS requests, then removes all three packages.
It does not forward traffic or access external servers. Two applications have
independent UIDs; the active VPN owner queries getConnectionOwnerUid for their
original TUN tuples. Results include ordinary UDP DNS and Android's system resolver.

This proves basic UID attribution, not complete per-application DNS semantics.
Resolver caching/coalescing, Private DNS, IPv6, network changes and API 29 need
additional cases before making general platform claims. Transition failures are
retried within a bounded interval; missing attribution remains an assertion failure.
The fixture uses unique synthetic names and does not capture real DNS payloads.
