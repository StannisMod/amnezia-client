# Desktop OpenVPN native DNS hand-off

Status: native opt-in and service/caller source wiring implemented for the
currently representable policy, including Linux single-group scopes. The new
custom-port/DoT/SNI typed forwarding path passed current-runtime Linux
private-resolved service tests (v315–v317): UDP/TCP clients, local AAAA NODATA,
selected custom plaintext ports, authenticated DoT, wrong-name refusal,
policy-change replacement and confirmed restore. Malformed policy recovery
retains owned aliases/journals. This is not actual OpenVPN tunnel acceptance.
**Remaining metadata/platform adapters and native
end-to-end acceptance remain unfinished and block merge.**

This is part of [IPv6-OFF DNS](IPV6-OFF-DNS.md), not a new DNS policy.
In particular, encrypted DNS metadata must not be flattened into plaintext
forwarding or used to bypass existing strict-DNS compatibility guards.

## Native side

The checked OpenVPN 2.7.0 recipe overlay adds `management-external-dns`. It requires
an IPv4-loopback management client and is not accepted as a pushed server option.
It is deliberately separate from ordinary `management-up-down`.
Desktop explicit OFF requests service-managed configuration; the service, not
the GUI, supplies the native management endpoint and external-DNS option.

In this opt-in mode:

- `run_dns_up_down` does not publish or restore OS DNS. Windows' live TUN options
  copy has its DNS servers/search/domain/registration removed before driver
  configuration; the original options remain unchanged.
- The existing native DNS serializer exports the selected modern DNS options,
  including transport/SNI/DNSSEC/domains. Additional fields retain actual server
  priorities. Windows legacy DNS occurrences, IPv4/IPv6 order within each family,
  domain and search list are exported from the original options, not the detached
  live copy. Unix legacy `foreign_option_N` remains the native source.
- A complete export replaces stale DNS environment keys, including removed
  servers, SNI and search entries. It is not a merge with an earlier selection.
- A new UP frame carries `amnezia_native_dns=external` and the actual native route
  result. Failed or unmanaged initial routes cannot reach DNS publication.
- After the UP frame the process waits for
  `AMNEZIA-DNS-PUBLISH:<serial>` NEED-OK confirmation. Exact `ok` is required.
  Each request uses a fresh, non-wrapping process-local serial so a delayed
  confirmation cannot authorize a later request. These are generation labels,
  not authentication secrets.
- Immediately before actual native teardown it requests
  `AMNEZIA-DNS-RESTORE:<serial>`. A failed query, disconnect or non-`ok` response
  keeps teardown blocked, with a one-second pause between attempts.
- A soft restart retaining `persist-tun` does not restore/remove a still-active
  guard. Its next UP frame is explicitly marked `preserved`, not falsely labelled
  as a new `add_routes` success, and also requires publication confirmation.
- The ordinary ON path does not wait for these acknowledgements or suppress DNS.
- Caller up/down/route scripts are refused in this mode. The application omits
  only its exact bundled resolver script, not arbitrary provider code.
  Script omission follows the pinned inline-file closing-tag rules and does not
  edit credentials inside literal or quoted inline blocks (v5 session tests).

## Service owner implementation and remaining scope

`OpenVpnDnsSession`, process IPC and `OpenVpnProtocol` now implement the control
ownership below in source. This is not a claim of installed-service acceptance:

1. Own the management connection and cleanup state in the existing service, not
   solely in a GUI callback. Retain original and negotiated DNS metadata.
2. Omit the application's bundled resolver up/down script only when the native
   external-DNS protocol is actually enabled. Suppressing the builtin publisher
   does not neutralize a separately configured script or administrator override.
3. Accept publication only after a complete external UP frame and native route
   proof. Accept `preserved` only for the same already-owned, route-confirmed
   native interface and generation, never as initial route proof.
4. Prepare real listeners/aliases, durably snapshot original OS DNS and the
   intended publication, then publish the selected DNS through the service
   transaction without losing resolver order/scope/metadata.
5. Send `needok '<exact request type>' ok` only after publication is confirmed.
   On publication failure, confirm rollback/retirement before sending `cancel`:
   cancellation can terminate native initialization. If rollback is uncertain,
   retain cleanup ownership and leave the native request blocked.
6. Acknowledge RESTORE only after OS restoration and owned cleanup are confirmed.
   Failed restoration must retain the interface, listeners, journal and owner;
   `terminate`, `close`, replacement and shutdown must honor the same condition.
7. Handle guard failure, lost GUI, retries, native reconnect, process exit and
   service startup recovery. Forced OS/process termination is not graceful
   restore acceptance; durable recovery must not delete ambiguous state.

The selection adapter retains resolver occurrences and numeric ordering, and
journals the native DNS metadata. It accepts legacy unscoped servers
and a single modern group with exact ordered ports and plain/DoT transport.
DoT retains the selected SNI (or normal IP certificate identity when absent),
uses normal CA/name validation and has no plaintext fallback. The guard receives
this typed resolver policy before preparation and journals it before alias
mutation; changed transport/port/TLS identity cannot reuse old forwarders.
This new desktop transport path still requires current native/runtime acceptance.
Linux additionally publishes modern
search/resolve domains and legacy DOMAIN/DOMAIN-SEARCH through a policy-aware
resolved snapshot. Other platforms still refuse scopes/search domains.
It still explicitly refuses DNSSEC settings, native DoH without an original URI
contract and multiple modern policy groups;
none is silently stripped or downgraded. Policy-aware OS publication for these
cases remains unfinished. Strict encrypted-DNS compatibility constraints still
apply; no TLS bypass is authorized.

`openvpn-scoped-publication-20261124-v3.log` measures actual Linux publication
and confirmed restore, mixed search/routing domains, duplicate IPv6-only
endpoints with UDP/TCP NODATA/SERVFAIL, scoped-to-global replacement with a
previously unaffected peer's root domain, and alias/journal removal.
Session 10 passed, transaction 14 passed, service 15 passed / one child-only
skip, eight production TUs compiled. This is not a native TLS/QtRO measurement.

Source process shutdown retains the native owner while DNS cleanup is pending.
A timeout does not authorize dropping uncertain DNS state. Once DNS/aliases are
confirmed restored, a three-second graceful-stop deadline can permit forced
native termination. This process/SCM/launchd workflow still needs actual runtime
acceptance; the session tests measure the control-state permission boundary.

## Measured evidence

Latest reconnect continuation:
`openvpn-tls-reconnect-20261125-v2.log` passes real SIGUSR1/persist-tun TLS
reconnect with no GUI replica process. Native PID, service DNS owner, interface
index and aliases remain unchanged; UDP/TCP NODATA/SERVFAIL pass after reconnect,
then reattachment and restore-before-TUN-teardown complete normally. Native v11
uses the actual retained c1.tuntap name in the preserved frame: the initial
v1 attempt exposed missing `dev` after c2.es recreation and was correctly
refused. Its failed log is preserved. Helper/overlay tests and offline full
native rebuild are in `openvpn-native-preserved-interface-20261125-v11.log`.
This is not retained-TCP, full-GUI or installed-service acceptance.

Current real Linux continuation:
`openvpn-tls-qtro-20261124-v9.log` executes the fully linked current service
and the offline rebuilt native v10 binary. TLS 1.3, CA and server EKU validation,
server-pushed scopes, private resolved, actual UDP/TCP NODATA/SERVFAIL before
and after SIGKILL of a separate QtRO replica, reattachment and graceful stop
all pass. `reattached-stop.log` records restore ACK before TUN closure and
`CONFIRMED_FINISHED 0 QProcess::NormalExit`; aliases/journal are gone.
Native and service hashes are recorded in the driver log. v1-v8 failure logs
are preserved, not relabeled. This is a console service plus a small QtRO
client, not full GUI/installed-service, other platforms, retained-TCP/split
or complete IPv6 containment acceptance.

The run exposed and fixed bypassed Linux/console factory initialization,
native restore queries aborted by pending shutdown signals, repeated QtRO root
registration and a management-close/normal-exit kill race. Restore queries alone
can ignore the already pending signal while waiting for ACK; the original
native signal is retained and ordinary credential-query behavior is unchanged.
`openvpn-post-tls-regression-20261124-v1.log`: 10 session, 14 transaction and
15 service tests pass (one child-only skip), plus eight production TU compiles.

Earlier evidence below is retained for provenance, not current native hashes:

`openvpn-native-service-activation-20261124-v7.log` records a complete Linux native
rebuild and execution of `--version`, offline with the existing configured
Conan source/dependency paths, 2 CPU / 4 GiB and no host-swap allowance.
That run failed a fixture assertion: /dev/null was rejected by X_OK before the
ownership guard. The v7 binary and failed manifest are unchanged. The independent
v9 activation report executes the corrected /bin/true fixture against those
exact bytes, measures the intended ownership refusal and compares actual
baseline/candidate loaded-library paths/SHA256 values.

`openvpn-service-real-dns-20261124-v6.log` records executed tests of the actual overlaid `do_route`,
`run_dns_up_down`, `do_close_tun` and metadata-export wrapper with instrumented OS
boundaries. Cases include publication/route failures, blocked/confirmed teardown,
retained `persist-tun`, unchanged ON calls, stale metadata removal, native
priorities/order, and ASan/UBSan export checks. The production native helper is
also compiled/executed in Linux and Windows preprocessor branches.
Both ordinary/down-pre close paths and the early untyped DCO close path are
exercised. The rebuilt binary also rejects missing, nonlocal and non-client
management configurations at the intended option-validation boundary.

The v6 service log additionally records:
- Session/selection/script tests: 10 passed, including reentrant stop,
  failure/rollback, nonce replay, preserved-owner checks and GUI-observer loss.
- Generic transaction tests: 14 passed. A refused publication/failed preparation
  does not reset an uninitialized platform interface; legacy ON ownership is
  protected from a foreign ticket.
- Real service/alias/resolved tests: 13 passed, one child-only skipped slot.
  The production session and selector call real DnsUtilsLinux/ServiceGuard and
  the actual existing DNS-enabled Xray runtime. Two duplicate IPv6-only
  upstreams produce distinct endpoints and real UDP/TCP NODATA/SERVFAIL.
  Preserved replacement, durable native metadata, external-DNS refusal and
  restoration-before-alias-removal are exercised.
- Eight changed production TUs compile with newly generated current RPC headers.
- CMake imports the actual runtime target, including inherited include-order
  coverage; no replacement C ABI implementation is used.

The native management peer in the service test is modeled. A deleted GUI
observer is not an executed QtRO disconnect of the real client. Full linking,
installed service shutdown, actual native TLS/OpenVPN/split/retained-TCP and
Windows/macOS acceptance remain required; these measurements do not replace them.
