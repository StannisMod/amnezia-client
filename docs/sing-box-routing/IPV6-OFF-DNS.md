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
  Other native packets remain with their original backend.
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

## Work remaining

1. Shared primitive implemented under `native/routing/dnsguard`: an in-memory
   frontend handles UDP/TCP DNS over IPv4/IPv6. AAAA is answered locally; A uses
   an explicit scoped exchange preserving UDP/TCP. Parent cancellation closes
   the frontend and pending exchanges. A native TUN wrapper intercepts only
   the configured managed-DNS address; other packets and TUN headroom pass
   unchanged. Packet tests and ten race-instrumented repetitions passed locally
   in the bounded 2-CPU/4-GiB offline laboratory. **Not wired into a product
   backend yet.** Native adapter scope/lifetime integration remains required.
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
3. Audit Android/desktop native WG, OpenVPN, Xray and Windows IKEv2 paths against
   the same policy; add adapters where managed DNS is not already intercepted.
4. Test each adapter's real UDP/TCP DNS and IPv4/split/teardown behavior.
5. Re-run the affected hosted gates. Existing green runs at `8679f05` are the
   previous baseline, not evidence for this newly explicit requirement.

Do not claim universal support while only the shared primitive is implemented.
