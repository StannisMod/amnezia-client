# Android OpenVPN IPv6 packet regression

This package exercises the installed application's **OpenVpnService**, its real
OpenVPN3 JNI library, a real Android TUN, and an independent local TLS server.
It covers full capture, IPv6 inclusion/exclusion, IPv4-only servers and stale
cached IPv6 capability. GUA, ULA and NAT64 origins answer `VPN` only when the
sender belongs to the authenticated tunnel pool. Each origin must first be
reachable as `NATIVE` without VPN. Two original IPv4 TCP sockets must remain
usable throughout every case.
TCP and UDP on the application's IPv6 loopback (`::1`) must also remain local;
capturing the IPv6 default must not redirect local listeners into the tunnel.

It does not test DNS, MTU recovery, physical devices or other VPN protocols.
The API28 regression was initially attributed to stale IPv6 route-cache state
after scope changes; the follow-up below identifies a publication race instead.
The compiler now retains `::/0` when there is no IPv6 exception, instead of
artificially subdividing the default and subtracting kernel-owned loopback.
The ordinary x86_64 APK from `9a64032` passed all seven cases on API28 and API35,
including local IPv6 TCP/UDP. The exclusion case now uses `fd99::4/128` and
checks that adjacent `fd99::5` remains captured. Both exact Qt-produced exclusion
profiles contain 128 IPv6 routes. The previous broad `fd00::/8` exception also
passed before this fixture was strengthened; no extra cases were added.
Root cache flushing is a separate causal experiment, never part of a passing
regression or a production fix. An API35 pass alone does not close this gate.

The follow-up API28 reproduction on 2026-11-19 includes the ordinary AWG
compatibility prelude and four complete OpenVPN scope cycles. The unchanged
hosted APK leaked `fd99::5` through NATIVE in the fourth exclusion case.
A capture-source prototype supplied `100::2/128` from RFC 6666's discard-only
prefix when OpenVPN had no negotiated IPv6 address. It passed the repeated
IPv4-only cases, but later leaked `fd99::5` in a dual-stack case with a real
negotiated IPv6 address. It is **not** an accepted fix and was removed from
production source; the prototype, source patch and failure evidence are kept.

Packet metadata then confirmed a native-path TCP connection followed, without
any route changes, by VPN-path connections one second later. Android 9's
`ConnectivityService.handleUpdateLinkProperties()` stores the new properties
before calling `updateLinkProperties()`/`updateRoutes()`; the corresponding
`CALLBACK_IP_CHANGED` follows the netd route updates. Polling the getter, or
checking only the first IPv4 route, therefore does not establish IPv6 readiness.
Primary source: [Android 9 ConnectivityService](https://android.googlesource.com/platform/frameworks/base/+/android-9.0.0_r61/services/core/java/com/android/server/ConnectivityService.java).

The production correction registers a VPN callback before establishing the
final TUN, identifies that TUN from its own descriptor's `fdinfo`, and waits for
its complete address/route publication before returning the descriptor to
OpenVPN. An old agent with a reused interface name and an intermediate TUN
cannot satisfy the gate. Timeout/loss fails startup; disconnect cancels the
wait. No synthetic address, fixed sleep, route mutation, socket rebinding or
policy expansion is used. The final local prototype passed eight complete
scope cycles in each server mode, eight TCP probes per destination and UDP:
32 IPv4-only plus 24 dual-stack cases, 2016 IPv6 assertions. Hosted verification
of a source-coherent production APK remains required.

The failing destination and case can vary with the preceding scope and timing; the
observed bypass is not limited to the exclusion case or IPv4-only servers.
Local experiments with an intermediate full-IPv6 TUN, a new NetworkAgent, and
waiting for its LinkProperties callback still reproduced the bypass. One
polling-based intermediate-TUN run passed all seven cases, but the subsequent
callback-based run failed. None of these experiments is an accepted fix, and
none is part of the application's production connection path.

## Run locally

Use an owned disposable, rooted x86_64 emulator container with an isolated
network namespace (`--network none`) and an ADB server reachable inside that
namespace. Install SDK `platform-tools`, `platforms;android-36` and
`build-tools;36.0.0`. The SDK, checkout and original APK are mounted read-only.
No Docker socket or host network is used by the test container.

From the repository root:

```sh
docker build -t amnezia-openvpn-tests scripts/routing/android-openvpn
mkdir -p openvpn-test-results
docker run --rm --network container:YOUR_OWNED_EMULATOR \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e ANDROID_HOME=/sdk \
  -e PATH=/sdk/platform-tools:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -v "$PWD:/src:ro" -v "$ANDROID_HOME:/sdk:ro" \
  -v /absolute/path/to/apks:/input:ro \
  -v "$PWD/openvpn-test-results:/results" \
  amnezia-openvpn-tests --apk /input/AmneziaVPN-x86_64-debug.apk --work /results
```

Pass `--apk-source-sha` only when the APK's actual source commit is known.
Unknown Git metadata remains unknown; APK, policy and harness file hashes are
recorded. `--case full|include|exclude` runs a focused diagnosis and reports
`PASS_FOCUSED`, rather than claiming the complete suite passed.
`--scope-cycles 4` repeats all applicable cases in each live server fixture;
the default remains one cycle. CI uses four cycles on API28 to retain the
warmed-routing regression rather than treating a cold single-cycle pass as
proof that the bypass is gone.
`--tcp-probes 8` checks eight independent TCP sockets per destination and case.
Every probe is asserted; the first mismatch still fails, rather than being
retried into a pass. CI combines this with four API28 scope cycles.

The driver accepts only an emulator (`ro.kernel.qemu=1`), reinstalls a disposable
re-signed copy plus its separate instrumentation APK, and verifies all native
payload bytes are unchanged. It replaces temporary test device ownership and
sets emulator Private DNS off. Use a disposable emulator, not a personal device.
The input APK is never modified. Test credentials and fixture-bearing APKs are
removed on completion; reports and logs remain under `/results`.

## Normal regression integration

The existing Android acceptance job runs this package in its API28 and API35
AWG lanes; it does not add another job or duplicate it in the WireGuard lanes.
No run is dispatched by this package. The host fixture is allowed only on a
verified disposable GitHub-hosted runner or in the isolated Docker namespace.

`client/tests/data/openvpn-tun-builder-policies.json` is checked against the
actual Qt configurator by the ordinary `ConnectionTest`. Normalization removes
only empty lines and the desktop-only resolver hooks absent on Android. Routing,
blocking and capture markers remain part of the comparison. Updating the
producer requires reviewing this fixture; a stale hand-written profile cannot
silently stand in for production configuration.

On failure the suite preserves routing tables, policy rules and socket marks.
An already incorrect socket stays open briefly for observation, while its
original mismatch still fails the test. The test never silently retries an
incorrect packet into a pass.
