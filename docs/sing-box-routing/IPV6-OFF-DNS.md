# IPv6 OFF: DNS policy across native backends

Decision: user confirmation, 2026-11-20. **Not complete; blocks merge.**

Explicit OFF must return AAAA NODATA in every backend, not only shared routing.
It must also retain IPv6 capture and reject cached/literal IPv6, without changing
IPv4 application routing, DNS scope, TLS validation, or ON behavior.

## Integration constraints

- Reuse the existing Go runtime and pinned packet/DNS dependencies.
- Do not migrate all native traffic to a flow proxy just to filter DNS: that
  could change native IPv4 protocols, split scope, and lockdown behavior.
- A DNS-only packet frontend may own only its configured DNS capture address.
  A native-engine upstream exchange is additionally restricted to the selected
  DNS peer, original tunnel source and exclusively reserved transport ports.
  This is not an application dialer or permission to migrate other native
  traffic. Other native packets remain with their original backend.
- DNS forwarding must use the connection's selected DNS path. Missing or
  unavailable forwarding must fail closed, never fall back to public/underlay
  resolvers.
- User clarification, 2026-11-21: OFF blocks IPv6 transport including DNS
  control traffic; there is no privileged IPv6 DNS exception. Local AAAA NODATA
  uses an IPv4 managed endpoint. An IPv6-only selected upstream is unavailable
  under OFF; other queries fail closed rather than silently changing resolver
  or scope. Existing explicit multiple-resolver selection remains authoritative.
- Cover UDP and TCP DNS, A preservation, upstream failure and cancellation.
  A UDP-only interceptor is not sufficient.
- This is plaintext DNS policy, not permission to decrypt DoH/DoT or bypass
  certificate validation. Existing strict-DNS compatibility guards remain.
- A native frontend must start before publishing its DNS settings and stop
  with its connection; failure cannot publish a nonfunctional DNS address.

### Android OpenVPN native-engine upstream integration

The public Android VPN Network socket bind checks whether the calling UID is
in the VPN's application ranges. In AOSP Android 10, netd's `SELECT_NETWORK`
calls `checkUserNetworkAccessLocked`, and `VirtualNetwork::appliesToUser`
tests those UID ranges; being the provider/protectable UID is not a bypass.
The provider may legitimately be excluded by an include-only app split.
Do not add its UID or change the user's app scope to make DNS bind succeed.

The current OpenVPN integration instead reuses the existing DNS capture stack
in libck for these DNS-only upstream connections. Unconnected/non-listening
IPv4 kernel sockets reserve ports; actual packets use the original native
tunnel IPv4 source and MTU and are posted onto the existing engine thread.
Decrypted replies enter only those leased DNS connections in the same stack.
There is no second stack, TUN reader, process network binding or resolver
substitution. DIRECT still requires the pinned original public network bind.

Queued engine sends check current capture/strict-DNS admission. A joined gate
cancels pending payloads and fences late callbacks before native retirement;
whole policy release still requires native worker return and DNS stop/join.
Unknown application fragments retain their original native/kernel path.
Identified leased-DNS first fragments are consumed, preventing duplicate
kernel TCP reassembly/RST; out-of-order selected-peer fragments may be copied
for reassembly without consuming unidentified application traffic.

These are implementation constraints, not a claim of Android runtime or
physical-device acceptance. The chronological host/build measurements are
recorded in `STATUS.md`; actual VPN/app-split acceptance remains outstanding.

## Work remaining

Current implementation checkpoint (2026-11-23): native Apple WG/AWG and
OpenVPN wiring passed the complete hosted matrix at `9ae44af`; HEV reader and
joined-stop preparation passed at `d6114dd`. Native Apple Xray activation is
implemented at `7751c9c`; hosted run `45141358149` passed Apple checks, but its
overall gate failed the Mac Intel retained-TCP/MTU latency bound (unresolved).
The chronological
notes below describe the stages that led here, not the current wiring status.
No physical Apple adapter acceptance is claimed. Android/desktop native paths
and Windows IKEv2 still prevent universal completion.

1. Shared primitive implemented under `native/routing/dnsguard`: an in-memory
   frontend handles UDP/TCP DNS over IPv4/IPv6. AAAA is answered locally; A uses
   an explicit scoped exchange preserving UDP/TCP. Parent cancellation closes
   the frontend and pending exchanges. A native TUN wrapper intercepts only
   the configured managed-DNS address; other packets and TUN headroom pass
   unchanged. Packet tests and ten race-instrumented repetitions passed locally
   in the bounded 2-CPU/4-GiB offline laboratory. Initially not wired into a
   product backend; native Apple wiring is now implemented as described above.
   The asynchronous native-exchange bridge validates response identity/question,
   rejects duplicate/late replies, cancels native I/O before releasing its owner,
   bounds admission and never selects a fallback resolver. The Apple C ABI has
   an executable C-client test against the real Apple parent dependency graph.
   Both that test and ten parent-graph race repetitions passed on Linux from
   existing caches. This is not Apple SDK/runtime acceptance. Hosted iOS CI now
   checks the exported symbols and runs the C client against its unified host
   library in addition to the existing packet-flow ABI test.
   Baseline `b0cbffc` passed that hosted matrix, including the Darwin C client.
   `NativeDNSGuard.swift` now provides the next host layer: typed UDP/TCP
   dispatch, explicit per-request cancellation, early native failure rejection,
   spurious-response handling, safe asynchronous callback teardown and packet
   classification. iOS/macOS targets include it, with new SDK and executable
   Swift/C-bridge tests in CI. This host layer still needs connection-lifecycle
   wiring; it is not enabled for users.
   `NativeDNSResolver.swift` adds explicit tunnel, physical-interface and
   loopback scopes; numeric endpoints only; UDP retry on the same connection
   (maximum three, ordinary queries only); and TCP DNS framing. Modern Apple
   tunnel requests require the public virtual interface, with the public
   through-tunnel APIs on older supported OS versions. Missing scope fails
   closed. SDK/loopback transport tests and full iOS app/extension builds passed
   in job `136366795882` at `2180e7f`. Protocol settings, original
   DNS-route-to-scope mapping and strict OFF enforcement for resolver transport
   remain to wire. No IPv6 DNS control-plane exception is authorized.
2. Integrate native Apple WG/AWG and OpenVPN without a second packetFlow reader
   or Go runtime, preserving transport socket ownership and native non-DNS I/O.
   OpenVPN connection wiring is now implemented via `NativeDNSController`,
   pending SDK/lifecycle/route tests. It stages before DNS publication, commits
   or rolls back generations, intercepts only reserved endpoints in the existing
   reader, and stops on disconnect/fatal error. IPv4 DNS scope is selected from
   the native connection's public routing policy and connected-underlay snapshot,
   then bound explicitly, never retried through a default dialer. iPhoneOS has no
   public net/route.h; the attempted RTM_GET implementation was removed after
   hosted compile failure. Arbitrary external routing-table overrides and actual
   adapter-level VPN runtime acceptance remain unverified.
   Native WG/AWG wiring now reuses the same controller, with the Go backend's
   existing TUN reader invoking a synchronous filter from the existing unified
   runtime. IPv6 is rejected there; ordinary IPv4/native protocols pass
   unchanged. Registration spans temporary native backend restarts and is
   released after backend Stop joins callbacks. Local filter race/C ABI/overlay
   tests passed; SDK and real adapter runtime verification are pending.
3. Audit Android/desktop native WG, OpenVPN, Xray and Windows IKEv2 paths against
   the same policy; add adapters where managed DNS is not already intercepted.
4. Test each adapter's real UDP/TCP DNS and IPv4/split/teardown behavior.
5. Re-run the affected hosted gates. Existing green runs at `8679f05` are the
   previous baseline, not evidence for this newly explicit requirement.

Do not claim universal support while only the shared primitive is implemented.
