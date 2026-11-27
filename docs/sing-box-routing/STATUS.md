# Implementation checkpoint — automated validation

## Active native runtime integration — local work, no intermediate CI

2026-11-27 resource-scope clarification: owner confirmed that aggregate local
2 CPU / 4 GiB / zero extra swap applies to this PR's verification workloads.
Unrelated parallel two-hop session containers are not owned by this task and
must not be stopped or modified. Continue this PR's builds/VM sequentially
within its own aggregate limit; the Android emulator remains stopped.

2026-11-26 Android OpenVPN continuation (v223–v233; NOT device acceptance):
- v223 SDK compilation rejected `Os.getsockoptInt`. The unused Kotlin socket
  helper was removed, not replaced with reflection/hidden APIs. Selected-scope
  socket I/O remains in existing libck/Go; Java only uses public Network binding.
- v224/v225 measured joined scoped exchanges, no IPv6 socket exception, and
  UDP4/TCP4 refusal before connect when original scope binding is unavailable.
  v226 shared-publication/OpenVPN Kotlin baseline passed 92 tests.
- Controller wiring now retains the native owner until connect-worker return,
  DNS callback join and transport-policy release. Fresh native generations retain
  ordered resolver/search occurrences; tunnel binds pin the published Network,
  DNS aliases and interface state. Preparation is a separate cleanup barrier.
- v227 passed 23 dnsguard race tests including quiesce, local AAAA NODATA,
  no forwarding while quiesced, and refusal to resume an unjoined old bind.
- v228 failed before compilation because Android Gradle used read-only
  `/root/.android`; failure evidence retained. v229 passed compilation and
  102 Kotlin/JUnit tests, 14 executed / 48 up-to-date in 32s. Writable
  ANDROID_USER_HOME points into existing cache, not a copied SDK.
- v230 actual libck C ABI + C++ ASan/UBSan, four Cloak race cases, Android
  ovpncli/director syntax and SWIG API passed. v231 additionally passed real
  loopback UDP/TCP selected-resolver forwarding with pre-connect AF_INET bind
  admission; native product cache hit, source bytes rewritten 0.
- v232 current controller partial-preparation retention compiled and passed
  102 tests, 5 executed / 57 up-to-date in 16s; source delta 13,313 bytes.
- v233 current arm64 Android c-shared libck linked with frozen source/binary
  dependency verification; SHA256
  `79b64ad65e81cd595fa1e02791441ec58a1d9b7560c640fac88ae61cc4d910cd`.
  It is not a production libovpn3 link or VPN/device runtime result.
- Production recipe/CMake/Java staging edits are IN PROGRESS, not accepted yet.
  Same-build generated Java replaces checked-in wrappers. Incremental package
  staging replaces whole-tree deletion; 6 staging and 4 source-isolation tests
  executed successfully. Full native recipe/build/package integration, aggregate
  all-ABI checks, blocked-bind C ABI retirement, service compile and device/
  hosted acceptance remained required at that checkpoint.
- v234 production build FAILED at final link: Base64 in the SWIG director
  exposed duplicate OpenVPN globals. The director now declares them extern;
  v235 linked with 3 incremental actions, without rebuilding archives.
  v236 exercised the actual package method, JNI exports and DT_NEEDED to libck.
  v237 compiled same-build generated Java, not a fixture, and passed 102 tests.
- v238 deployment adoption refused unowned OpenVPN inputs before writing.
  Measured hashes matched retained v226 inputs; explicit baseline adoption
  enabled v239 full service/app compilation: 12 executed/54 up-to-date, 47s.
- v240's blocked-bind fixture incorrectly expected DNS stop to release policy.
  v241 measured the distinct barriers: owner retained during blocked callback,
  late success sent no UDP after quiesce, stop joined, then policy released.
  Actual C ABI/ASan/UBSan and Android syntax passed.
- v242–v244 linked frozen libck for armv7/x86/x86_64 (arm64 v233), with
  source/binary provenance, source rewrite 0. v245 packaged original Cloak
  licenses/source graph/provenance; Ninja reported no work. v246 passed 102
  tests with native terminal errors deferred until confirmed retirement.
  v247 actual package staging wrote 14,752,295 bytes once; identical second
  staging wrote 0 bytes, with unchanged file hashes AND mtimes.
- v248–v250 linked production libraries for remaining ABIs. These and v253–v256
  are NOT evidence of the later metadata guard everywhere: a newly added shadow
  header was absent from old compiler depfiles. Explicit owned-overlay
  OBJECT_DEPENDS fixed incremental invalidation. v257–v260 linked all four ABIs
  and measured that the real ovpncli TU consumed EVERY required overlay
  (base/client/tunprop/resolver). Arm64 libovpn3 SHA256:
  `aa75b860b68929ea936f4f63ba5a873824abbf9e69c8f2c3df5a4c968db9ee8e`.
- Stock OpenVPN3 flattens modern transport/SNI/DNSSEC/ports/domain groups.
  OFF now refuses unrepresentable final DnsOptions BEFORE that callback boundary;
  complete ordered modern search domains are retained, explicit adapter suffix
  is refused rather than erased. This is a safety barrier, NOT full support.
  v251 host metadata fixture failed for missing Asio/log preamble; v252 fixed
  the fixture and passed actual-struct policy cases, C ABI/ASan/UBSan and Android
  syntax/SWIG. Production staging now ships original Cloak notices/provenance.
- v261 current controller/generated-Java compile and 104 tests passed:
  5 executed/58 up-to-date, 17s. Added exact ordered-alias and lost-handle tests.
  v262 current full service/app compile passed: 4 executed/62 up-to-date, 27s.
  Still unfinished: faithful modern metadata/platform adapters, actual Android
  VPN/runtime acceptance, complete packaging/CI integration and remaining
  cross-platform acceptance. No push, hosted dispatch or merge.
- v263/v264 current arm64 packaging and explicit unchanged-content cache check
  passed: both Ninja runs reported no work; second packaging reused the SAME
  immutable content-addressed package. Package identity now follows actual
  libraries/Java/headers/notices, not a recipe-only edit or run/workspace name.
  Existing products/evidence were retained. Public headers are limited to the
  generated libck ABI and its native DNS declarations.
  Local package/source/cache suite: first combined invocation had an import-path
  harness error; corrected PYTHONPATH invocation passed all 28 tests.
  v265 native port-aware callback, actual DnsOptions/ASan/C ABI and Android
  syntax/SWIG passed; v266 compilation and 106 Kotlin tests passed (35s,
  16 executed/47 up-to-date). Exact per-occurrence custom ports and IPv6-only
  unavailable ports are retained; mismatched/invalid port lists fail closed.
- v267 existing-runtime encrypted exchange primitive passed race tests:
  authenticated selected-scope DoT for UDP/TCP clients, DoH POST/GET, rejected
  redirects/types/oversized/mismatched replies, CA/name failures, no IPv6
  transport and joined cancellation of a blocked scope dial. Full nativedns
  suite passed with two existing owned-interface fixture skips; this is not
  platform/private-network acceptance. A subsequent SelectedResolver/session
  metadata hook and its additional negative case await the next measured run.
  Primitive TLS trust configuration has no insecure/custom-validation bypass
  and no HTTP proxy, redirect or background dialing pool. Native metadata
  export, original platform trust/profile semantics and full policy integration
  remain unfinished; encrypted support is NOT declared complete.
- v269 current arm64 production recipe linked with the selected-port callback
  and encrypted primitive, 5 incremental actions. Packaged libovpn3 SHA256
  `e2c42953580da2586937209d5c47aa2ce52b240b38a0e2ae5ed2c79f8bc0d545`;
  existing libck SHA256
  `709dea8ac63686ba324a9882fe4f17c65d311015ceac50e3a0178f05ff139f85`.
  v270 actual same-build Java/Kotlin passed 106 tests (19s, 6 executed/57
  up-to-date); v271 full service/app compile passed (43s, 11 executed/55
  up-to-date). These precede the subsequent selected-TLS callback wiring.
- v272 SelectedResolver/session transport hook and additional metadata-negative
  case passed the nativedns race suite with the same two owned-interface skips.
  v273/v274 selected encrypted libck C ABI, AF_INET TCP-only bind refusal,
  IPv6-only NODATA/SERVFAIL, actual DnsOptions policy and Android syntax/SWIG
  passed. System trust remains normal x509 verification, no insecure flag.
  Kotlin/native source now carries final selected DoT port/SNI to the same
  resolver occurrence; DoH without an authoritative URI, DNSSEC settings and
  multiple domain/priority groups still refuse rather than flatten.
- v275 failed a new shared-publication JSON assertion on Android's mocked
  JSONObject. The shared test target now uses the SAME already-cached
  `org.json:json:20240303` test dependency as Xray, not a production dependency
  or version upgrade. v276 compiled and passed 108 tests (26s, 10 executed/53
  up-to-date). Actual production link/service compile after selected-TLS wiring
  remains pending. v277 adds a test-only TLS upstream/CA to measure positive
  DoT/DoH through the REAL libck C ABI, including TLS name failure; result
  passed: real libck C ABI with host ASan/UBSan measured positive DoT/DoH
  forwarding for UDP/TCP clients, local AAAA NODATA without upstream bind and
  actual TLS name-mismatch SERVFAIL without fallback. The process-local test CA
  uses the normal system trust loader. This is NOT Android trust/device
  acceptance. This fixture is never exported or packaged into the application.
- v278 current selected-TLS arm64 production link passed (5 incremental
  actions), including consumed-overlay dependency audit and JNI symbols;
  v279 same-build generated Java/Kotlin passed 108 tests (18s, 6 executed/57
  up-to-date); v280 full service/app compile passed (44s, 10 executed/56
  up-to-date). Other ABI builds and actual VPN runtime remain outstanding.
- v281 nativedns and dnsguard race suites passed (1.172s/1.116s), with the same
  two caller-owned-interface skips. Native proxy Flows now uses
  SelectedResolver too: typed encrypted metadata cannot silently become
  plaintext in that adapter. The new flow test measures TCP4-only original
  resolver targeting, no AAAA dial and no failure fallback.
- v282–v285 current production native recipe builds passed for arm64-v8a,
  armeabi-v7a, x86 and x86_64, with consumed-overlay dependency and JNI-symbol
  checks on every ABI. Existing workspaces/dependency sources were reused;
  no SDK/build-tree copies or device execution. These include the v281
  SelectedResolver flow change, unlike v278.
- v286 measured UDP/TCP DNS origination with the original tunnel IPv4 source
  using the SAME existing capture stack. v287/v288 dnsguard race suites passed
  (1.125s/1.121s), including kernel-exclusive ports without listen/connect,
  capture UDP/TCP AAAA NODATA without engine I/O, original selected A forwarding
  and confirmed port release. These are host measurements, not Android UID/VPN
  runtime acceptance.
- v289/v290 actual libck C ABI + host C++ ASan/UBSan passed new tunnel DNS A and
  NODATA without any OS Network bind callback, unchanged unowned native packets,
  policy/host retirement, queued native engine cancellation and executing
  callback join. v290 Android compiler syntax/SWIG passed the current existing
  engine injection overlay and new tunnel preparation API. Kotlin/native
  production wiring is being checked in v291–v293; results pending.
  Native engine admission must still retain strict-private-DNS/current-capture
  checks before actual queued sends; the earlier OS bind did those checks.
  Fragment mirroring/classification, cancellation and encrypted native-engine
  forwarding need additional targeted measurements before acceptance.
- v291 production arm64 native-engine link passed. v292 new Kotlin test failed
  to compile because its InetNetwork constructor used a String instead of the
  existing InetAddress/prefix API; corrected without changing assertions.
  v293 was NOT executed. v294 native C ABI/ASan/SWIG and v295 production arm64
  link passed the queued-send strict-DNS/current-capture admission hook.
  v296 new test then exposed mocked JSONObject in OpenVPN's JVM test target.
  Added the same already-cached test-only JSON dependency used by Xray/shared
  tests. v297 was NOT executed. v299 passed 109 Kotlin tests (14s, 2 executed/61
  up-to-date), and v300 full service/app compile passed (30s, 5 executed/61
  up-to-date). These do not measure actual Android include-only VPN behavior.
- v298 host race suite passed original-MTU 576-byte engine output, fragmented
  large UDP query and 4-KiB response. Review identified that mirroring ALL
  fragments to the kernel could duplicate TCP reassembly and cause a kernel
  RST; therefore v298 alone is NOT fragment ownership acceptance.
  v301 race suite passed exclusive leased-DNS first-fragment ownership,
  out-of-order unidentified mirroring, cancelled-flow fragment fencing and
  unchanged application-owned first-fragment routing (1.121s). Additional
  native/kernel runtime acceptance remains outstanding.
  v302/v303 now check authenticated DoT over the same engine, zero-allocation
  unowned Go input and borrowed C-ABI input plus immutable native owner
  snapshots (no per-application-packet map copy); results pending.
- v302 passed authenticated same-stack DoT for UDP/TCP DNS clients, wrong
  CA/name refusal and 0 Go allocations/call over 1000 unowned native packet
  admissions (race suite 1.142s). v303 actual libck C ABI/ASan/UBSan and
  Android syntax/SWIG passed borrowed packet input and immutable owner snapshots.
- Review found that a single native engine mutex could block quiesce and
  reentrant stop behind an executing engine send. Separate pending-post and
  executing-send gates now cancel every scope before joining a callback.
  Go Resume additionally waits for pending engine writers, not just completed
  resolver handlers. v304 race suite passed the blocked writer retirement
  barrier (1.169s); v305 native ASan/UBSan measured prompt quiesce/enqueue while
  an engine callback was held, cancelled late payloads and confirmed close/join.
  v306–v309 current production builds passed all four Android ABIs, including
  owner/engine/options/bootstrap consumed-header checks, selected/tunnel JNI
  and exact existing-libck C ABI exports. Actual Android runtime remains pending.
- Desktop single-group OpenVPN custom-port/DoT/SNI policy now has an ordered
  typed handoff into the existing resolver runtime. Guards must accept it BEFORE
  preparation; a changed TLS identity cannot reuse plaintext/previous forwarders.
  Resolver policy is journalled before alias mutation and checked on recovery.
  v310 current Qt selection/session test and transaction/lifecycle tests passed
  3/3 CTest targets; current service C++ compiled/linked using a retained OLD Go
  archive solely as an ABI scaffold, NOT encrypted runtime acceptance.
  Current-runtime/private-resolved TLS acceptance is being added.
- v311/v312 offline desktop runtime preparation exposed disjoint existing module
  caches; no dependency versions/downloads were changed. A persistent symlink
  union now references their sources/download metadata with 0 module bytes
  copied. v313 still lacked metadata for two UNUSED Docker/mobile modules
  requested by `go list -m all`. The check now compares actual compiled module
  versions/replacements before/after against the original locked Xray binding,
  rather than fetching unrelated inactive platforms. v314 runtime build and
  parent-graph DNS race tests are pending; earlier failures are retained.
- v314 current existing Xray-runtime archive built offline, SHA256
  `7fc27c2d353a33dc13aa9842dce1d6b411534bfc7978a35d0b14741dd600cff1`.
  Measured compiled versions/replacements before/after are identical except the
  one local DNS module; parent-graph race tests passed with the same two
  caller-owned-interface skips (1.151s). Stable source writes were 0 bytes.
- v315 current C ABI + real private-resolved service suite passed16/failed0/
  skipped1 (the existing child-only crash fixture), including a child process
  using a process-local test CA through the normal system trust loader:
  UDP/TCP client AAAA NODATA, DoT A, TLS-name refusal, journalled resolver policy,
  changed-identity replacement and confirmed OS/alias restoration.
  v316 additionally measured original custom plaintext UDP/TCP ports and
  explicit transport changes. Fixture observed plain UDP1/TCP1, DoT2, DoH0;
  all 16 service cases passed with the same one child-only skip (676ms).
  The fixture remains test-only and is never packaged into production.
  A CMake custom target/output name collision produced circular-dependency
  warnings in v316; target name is corrected rather than suppressing warnings.
  v317 passed18/failed0/skipped1 (687ms), including malformed typed-policy
  refusal/recovery; fixture hash/mtime were unchanged, with no helper
  recompilation or circular-dependency warning.
  v318 repeated offline runtime/dependency/race checks passed (1.150s, the
  same two caller-owned-interface skips). Immutable archive was a cache hit;
  persistent source writes were 0 bytes, temporary overlay 130237 bytes.
  These measurements do not replace actual VPN/device/platform acceptance.
- v319 production-link harness refused the new immutable product because it
  expected legacy in-product dependency evidence. The linker now accepts the
  cache builder's separate measured graph, checks exact archive/header hashes
  and permits only its recorded added module. v320 then failed configuration
  because the wrong existing Conan volume was mounted; failure retained.
  The exact missing OpenSSL package was located in the existing
  `amnezia-local-full-build-ubuntu22` volume, with no fetch/copy/substitution.
  v321 configuration and all55 production compile/link steps passed against
  that original read-only closure, including Router, typed selection and
  native DNS service with the current v314 archive. Existing logger unchecked
  QFile::open warning remains; this is not installed-service/VPN acceptance.
  v322 desktop overlay/provenance regressions passed6/6, including refusal of
  altered archive/header bytes, changed dependency versions and an unrelated
  added module before build metadata mutation.
  v323 current production-generated Android Java/JVM incremental check passed:
  109 cached test results, all63 Gradle tasks up-to-date, 0 source bytes written
  (not a fresh test execution). v324 full Android service/app Kotlin compile
  passed (1 executed/65 up-to-date,10s). v325 actual current Java/license/AAR
  package staging passed; first incremental write569578 bytes, repeated staging
  0 bytes. These checks do not establish Android device/VPN acceptance.
- v326 expanded desktop runtime-import/provenance regression passed7/7.
  Source review against systemd's primary resolve1 API found that legacy `DNS`
  snapshots omit original endpoint ports/SNI. New snapshots now use `DNSEx`
  and `SetLinkDNSEx` when exposed, including metadata-only edit comparison.
  v327 measured successful custom IPv4/IPv6 port/name roundtrip and refusal to
  overwrite an SNI-only external edit, but the full suite failed its partial
  crash fixture: that fixture still filtered publication to the old `dns` key
  and therefore had not published the alias. Failure retained. Its predicate
  now includes `dns_ex`, without changing the alias/crash assertions.
  v328 corrected-fixture real private-resolved suite passed19/failed0/skipped1
  (715ms); v329 current production service recompiled/linked all12 steps.
  v330 source-integration invocation passed the 4 isolation,8 staging and4
  Windows overlay tests, but its aggregate failed because two executable
  harnesses are not unittest suites. v331 refused ambiguous cached source
  selection (two existing OpenVPN2.7 source trees). v332 invoked the real
  entrypoints against both existing trees: helper branches, real route/up/down/
  teardown functions and ASan/UBSan metadata-export checks passed.
  No assertion was weakened and no cache/source tree was discarded.
- v333 real private-resolved suite passed20/failed0/skipped1 (727ms).
  Recovery now records unchanged native/global DNSSEC/DoT modes, link multicast
  modes and negative trust anchors; publication/replacement/restore cannot
  silently adopt changed security policy. Enforced OS TLS/DNSSEC remains
  explicitly refused rather than disabled for the plaintext local frontend.
  This is safety coverage, not full native DNSSEC/OS encrypted-policy support.
- Windows selected native known-server DoH now has a pre-prepare typed-policy
  hook: exact original URI, numeric selected peer, port, TLS identity, ordered
  duplicate occurrences and native no-fallback policy are retained. Plaintext
  GPO prohibition is respected; unsupported fallback, per-interface properties,
  effective NRPT and unknown policies remain refused.
  The v2 durable policy reader is distinct from the retained v1 journal reader.
  v334 portable model/transaction/lifecycle CTest targets passed3/3;
  the service target outside its owned namespace is not OS acceptance.
  v335 VM harness failed before boot due to a Python http module/local-variable
  collision. v336 reuses its existing ownership/resource/shutdown functions in
  a corrected runner, preserving the historical script, VM and both disks.
  v337 native invocation failed before WinRM because system Python lacked winrm;
  the already-installed `/opt/winvm-venv` was used in v338.
  The incremental native source bundle is130937 bytes, with no SDK, toolchain,
  build-tree or VM copies. v338 actual MSVC adapter objects compiled and the
  transaction/lifecycle targets passed2/2. Native Windows known-server policy
  tests passed4/4 in each baseline, strict selected-DoH, unrepresented-fallback
  and inactive-mapping phase; the original URI/order/identity were retained and
  owned mapping removal was confirmed. This is not encrypted service traffic.
- v339/v340 inspected the actual cached Windows Xray source/toolchain.
  v341 current native Windows DLL/import library built offline with unchanged
  compiled dependencies/replacements plus the one local DNS module; parent-
  graph race suite passed (1.577s). DLL SHA256:
  `fbad01a11a27838597c388cac4f5bcb98036be3889d43f5abf503cfaab202dbd`.
  Native cross-process Windows cache locking was measured (1 test passed).
  Module bytes copied0;210 persistent links reference the existing cache;
  source staging130343 bytes. No SDK/toolchain/VM/build tree was copied.
  The test-only TLS fixture now uses P-256 certificates so the ordinary Windows
  chain verifier can be exercised; this is not a production trust-policy change.
  v342/v343 are retained, unexecuted small source bundles superseded before use.
  v344 native service fixture compile failed on missing netioapi declarations;
  v345 added the proper headers and the current-runtime service linked, then its
  runner failed before execution because CTest was outside the vcvars PATH.
  Both failures are preserved. v346 uses that existing tool environment and
  runs native service acceptance directly, with no forced-cleanup timeout.
  It also checks immediate quiesce when an active native-policy read refuses;
  v346 native transaction/lifecycle passed2/2, including immediate refusal
  quiesce; native service execution failed at CurrentUser ROOT fixture setup.
  v347 diagnostic invocation failed on PowerShell native-argument quoting;
  v348 measured valid DER/context but CurrentUser ROOT add error0x32.
  v349 measured successful LocalMachine ROOT add/delete of that exact fixture
  certificate and confirmed its thumbprint absent afterwards. The fixture uses
  this ordinary machine trust scope, not custom Go roots or TLS bypass.
  v350 reached real service traffic but failed the inherited1s wire-client wait.
  v351 isolated the normal Windows system verifier: unknown fixture root refusal
  took12056ms offline, without any trust/policy change.
  v352 observes that slow negative result to completion while retaining all
  security/wire/fallback assertions, original1s positive/name/NODATA client
  waits and the unchanged production exchange deadline. Actual service passed
  3/3 Qt cases (25945ms), with unknown-root UDP refusal12075ms/TCP24ms,
  authenticated DoH A18/35ms, wrong-name refusal17/10ms; fixture observed DoH2,
  DoT0, plaintext UDP0/TCP0. Policy-edit refusal, retained local NODATA/SERVFAIL,
  original-policy restore, alias/journal retirement and owned trust/mapping
  cleanup were confirmed.
  Its trace nevertheless shows extra TLS handshakes during system trust work.
  v353 is inspecting the pinned native verifier/API contract before closing the
  scoped-TLS invariant; v352 is not proof that implicit trust-fetch networking
  is absent, nor actual VPN or complete native-metadata acceptance.
- v353 read the pinned Go Windows verifier and public CryptoAPI contract.
  Its default chain builder permits CTL/root/AIA retrieval outside our selected
  dialer. The Windows scoped path now retains normal Go TLS CA/signature/name
  verification, with a per-request local OS-root snapshot, AND requires native
  Windows chain/SSL policy (including native chain-edge signature checks).
  Native calls are cache-only: no implicit root/issuer/CTL/revocation URL fetch,
  no ignored trust errors and no InsecureSkipVerify. TLS peers must provide
  their intermediate chain and the original trust anchor must be locally
  available; missing trust material fails closed, never downloaded/substituted.
  Explicit original closed test-root policies remain unchanged.
  v354 compile failed on the pinned x/sys Handle-typed CRYPT_E_NOT_FOUND constant;
  v355 uses its proper syscall.Errno conversion. Actual native parent-graph
  race tests passed (1.629s), including default-verification/bypass guards;
  compiled versions/replacements remained unchanged. New current DLL SHA256:
  `a0215dc1b416a792c3c2e242a987c5b21068f05ed757260372b603e0611aef07`.
  Source writes7112 bytes; module-cache bytes/links added0/0.
  v356 restored the strict1s client wait for ALL cases and passed native service
  3/3 (13722ms total). Unknown-root refusal13/24ms, trusted A17/38ms, native
  Windows Disallowed CA refusal8/12ms, wrong-name refusal9/32ms; local NODATA,
  refusal ownership and confirmed recovery/owned-store cleanup passed.
  Exactly8 TLS connections matched the8 explicit A requests, with DoH2,
  DoT0 and plaintext UDP0/TCP0: the earlier extra-handshake recursion is absent
  in this measured fixture. No TLS/system-policy checks were disabled.
  v357 now additionally tests the original native GET URI template, alongside
  POST, with exact method/connection accounting: native service passed3/3,
  failed0/skipped0 (17857ms). All ten explicit A attempts completed14/30,
  23/14,9/21,11/21,15/12ms (UDP/TCP pairs); exactly10 TLS connections,
  POST2/GET2 accepted queries, DoT0/plaintext0. This is selected native DNS
  service coverage, not actual VPN or complete metadata acceptance.
  v358 reads pinned Darwin verifier sources only; it is NOT local macOS
  native/runtime acceptance.
  Inspection found that pinned Go's Darwin systemVerify invokes native
  SecTrustEvaluateWithError without setting SecTrustSetNetworkFetchAllowed.
  The current non-Windows scoped helper is still a no-op: absence of implicit
  Apple trust networking is NOT established. Apple scoped trust requires a
  native no-network policy implementation and hosted native/runtime checks;
  exporting an anchor list alone must not drop user/admin deny or SSL policy.
  v359 production-input discovery failed on an assumed build/generators path;
  failure is retained. Corrected read-only v360 found the existing conan/
  imports still reference the historical runtime and production source lacks
  windowsdnsselection.h. Production integration remains unfinished; v356/v357
  test executables must not be presented as the production application.
  v361 inventoried existing production source hashes without copying its tree.
  v362 applied only the measured differing source delta (compressed45678 bytes)
  and replaced the existing Xray import with the measured v355 DLL/header/lib.
  Offline cached production configure/build completed successfully, including
  current Windows DNS policy/recovery/service objects and service link; the
  application target was also requested and remained incremental.
  Service SHA256:
  `42c5eec506ff43c562c512d2e61f57dbe9868cda6b0db55fec4541395eb6acdb`;
  client SHA256:
  `82966e46b18218f21ec528e16e12a9432042673de13013de5f51457fe1bc61e9`.
  This establishes production compile/link, not installation or VPN runtime.
  v363 normal guest shutdown (shutdown /s /t0, no /f) succeeded; the VM lifetime
  runner and docker wait returned0. Disks/evidence retained, no forced cleanup.
  v364 Linux common-source rebuild stopped before build because the selected
  read-only Conan volume lacks the expected historical module-cache path.
  Failure retained; rediscovering the original cache mount, no download/copy.
  v365 identified the second wrong default cache path before build; retained.
  v366 explicitly reused the original stability Conan cache, integration
  modules and recovery go/modules (no downloads). Actual parent-graph comparison
  passed without changing any existing compiled dependency; fresh native DNS
  race tests passed1.157s (two privileged-interface cases skipped, not accepted).
  Current Linux archive SHA256:
  `253b0ec6e986f254039f5f7d5a7bfe8dd44dc6afd1f7692370d6d192a3d3af3f`.
  This includes the new common scoped-TLS call. v367 current Linux production
  service configure/compile/link passed (66 incremental actions); license
  generation reported62 modules/58 unique notices/missing0.
  v368 Android build stopped before compilation on the wrong upstream mount;
  v369 uses the original Android work volume and recovery Conan cache.
  Reusable mount identities (not interchangeable):
  Linux runtime work=`amnezia-connection-recovery-full-build`, Conan cache=
  `amnezia-connection-stability-full-build`, extra modules=`/work/go/modules`.
  Linux production Conan closure=`amnezia-local-full-build-ubuntu22`.
  Android work/NDK=`amnezia-android-primary-core-build`, Android upstream/SWIG
  cache=`amnezia-connection-recovery-full-build`; integration modules=
  `amnezia-connection-stability-integration`. Keep all caches/evidence.
  v369–v372 current common TLS-hook Android OpenVPN production builds passed
  for arm64/armv7/x86/x86_64, including JNI/C ABI exports, actual overlay depfiles
  and same-build Java/package provenance. Two incremental actions per ABI;
  no native-engine or SDK/tree copies. v373 Xray parent/socks race tests passed
  (1.088s/1.207s) and actual arm64 JNI/AAR binding passed, bootstrap/tools
  copied0/0, source delta23616 bytes. AAR SHA256:
  `7669f72f54738854f5598634e11fcb3199398627f4ac5bd6f72e7314dc2efc06`.
  v374 service harness failed on a retained CMake Go path; v375 corrected that
  explicit path and compiled, then stopped because the chosen image lacks ip.
  Failures retained. v376 reused the cached openvpn-qt-lab image with ip:
  actual current native service/private resolved passed20/failed0/skipped1
  (3224ms; only child-only fixture skipped). DoT2/plainUDP1/plainTCP1,
  trust-failure refusal, DNSEx/security-policy and confirmed recovery passed.
  The shared CMake TLS-fixture builder now also wires the Windows test to the
  production import. Hosted Windows execution reads its exact generated DLL
  path rather than searching/copying a possibly stale runtime; no dispatch yet.
  Darwin scoped-trust implementation is now in progress: macOS snapshots local
  system/user/admin trust candidates, retains normal Go TLS verification AND
  requires native SSL/trust policy with issuer and revocation networking
  forbidden. It does not replace native deny/usage constraints with an anchor
  list. Unsupported iOS anchor enumeration and non-cgo system trust fail closed
  before dial; original explicit closed test policies remain representable.
  New hosted-only native trust/deny/name/no-fetch fixture is implemented but
  NOT executed yet; no Apple native/runtime acceptance is claimed.
  v378 production-imported Windows test compiled but failed to link: inherited
  production logger includes took precedence over the isolated test stub.
  Failure retained. The test targets now explicitly prioritize their stub
  includes and pin their executable output directory instead of inheriting
  the production service output directory.
  v379 production configure/build and actual native service test passed3/3,
  failed0/skipped0 (21462ms). Unknown CA14/30ms, trusted POST26/36ms,
  native Disallowed15/16ms, trusted GET17/36ms, wrong-name15/28ms.
  Exactly10 TLS connections, accepted POST2/GET2, DoT0/plainUDP0/plainTCP0;
  policy-edit quiesce, local NODATA and confirmed owned-state cleanup passed.
  Generated runtime provenance selected the measured v355 DLL directly,
  without searching/copying another runtime. Production service SHA256 remained
  `42c5eec506ff43c562c512d2e61f57dbe9868cda6b0db55fec4541395eb6acdb`.
  v377 VM also completed normal shutdown with runner exit0; no forced cleanup.
  v380 current Android full service/app compile against the measured v373 AAR
  and v369 same-build Java passed:66 tasks,1 executed/65 up-to-date (19s).
  This is compilation, not fresh JVM or device execution.
  v381 consolidated Python invocation incorrectly included CLI-only modules;
  v382 exposed missing cached-source environment and an invalid /src Git
  worktree reference in the container cwd. Both harness failures are retained.
  v383 supplied the actual immutable caches and ran outside that worktree:
  55 tests ran,54 passed/failed0/skipped1 (Windows-only lock; previously measured
  natively). Android/Desktop/Windows overlays, Apple/Swift/HEV preparation,
  package provenance/refusal and cache ownership checks passed.
  v384 actual current Android package-input staging passed; first delta
 13698811 bytes, identical second staging0 bytes with unchanged hashes/mtimes.
  Retained notice inventory is reused; dependency versions/licenses unchanged.
  Current Darwin sources passed pinned gofmt; native SDK/runtime verification
  remains required on hosted macOS. Hosted CI has not yet been dispatched.
  v385 final current-source Linux parent-graph/race/build passed (1.197s;
  two privileged-interface cases skipped here and covered by the v376 native
  service fixture). Compiled existing dependency graph unchanged. Archive
  SHA256 remained byte-identical to v366:
  `253b0ec6e986f254039f5f7d5a7bfe8dd44dc6afd1f7692370d6d192a3d3af3f`.
  Darwin-only sources did not alter the Linux runtime binary. Candidate push
  is for mandatory hosted native/platform verification, not a merge-ready claim.

Latest local checkpoint (2026-11-24, service-owned OpenVPN source wiring):
- 2026-11-25 Windows IKEv2 continuation (NOT complete native acceptance):
  Source now routes OFF dial/DNS/stop through the existing service and native
  RAS backend, with an immutable, owner-only snapshot of the original PBK bytes.
  Negotiated DNS comes from the unique connected PPP interface matched to the
  RAS projection; IKE server/MOBIKE addresses are not DNS fallback candidates.
  The service fences IPv4 DNS during dial, independently blocks IPv6, prepares
  the existing Go-runtime guard, and publishes only before reporting Connected.
  Stop retains ownership until DNS/aliases restore, RasHangUp joins by its
  documented invalid-handle proof, and protection retires. Durable RAS records
  and explicit completion receipts preserve uncertain/lost-reply boundaries;
  an ambiguous crash inside RasDial before its returned handle is committed
  remains fail closed, not relabeled as recovered.
  `windows-ikev2-dns-native-20261125-v6.log`: actual MSVC/Windows SDK production
  native adapter compilation, 7 lifecycle cases, 3 real UDP/TCP WFP fence cases,
  and real SCM STOP_PENDING/checkpoint 1→2/same-PID→normal stop all passed.
  The SCM fixture measures the real deferred-stop framework, NOT a RAS tunnel.
  `windows-ikev2-production-link-20261125-v1.log`: full normal Windows client
  and service linked offline, 310 build actions, frozen existing packages and
  measured DNS-enabled Xray runtime. It predates the subsequently added
  confirmed certificate-import result RPC and strong-profile error checking.
  A new normal-build actual-client IKEv2 target and v2 full build/install are
  in progress. The certificate-authenticated cached Libreswan fixture is ready,
  but no real negotiated IKEv2 acceptance result is claimed yet.
  Preserved failures: guest pre-login WinRM HTTP 500 (v1), manual MSVC Qt flag
  omissions (v2/v3), future ZIP wall-clock timestamps (v4), and SCM driver parse
  failure after successful compile/model tests (v5). Guest UTC matched host;
  only future extracted-source mtimes were normalized, with native source hash
  equality measured. No package downloads or acceptance assertion weakening.
  Windows installer CMD force-kill removal is currently source-only; MSI/IFW
  pre-payload restore gating and actual installer acceptance remain unfinished.
  Additional shutdown review item still open: a failed generic startup DNS
  recovery must remain an explicit LocalServer shutdown barrier, even when no
  new in-memory DnsUtils guard was admitted. An empty new utility is not proof
  that the old durable journal/aliases retired. Cover crash + external edit +
  fresh-service stop before declaring all platform lifecycle work complete.
  Active VM/peer limits are aggregate 2 CPU / 4 GiB / zero extra swap.
  `windows-ikev2-production-link-20261125-v2.log` linked the updated normal
  client/service and actual-client target (492 actions), then standard install
  failed resolving amnezia_xray.dll. Production CMake now explicitly deploys
  the actual imported Go DLL and searches its target/build directories.
  `windows-ikev2-production-deployment-20261125-v4.log` records successful
  standard install into a fresh prefix, with no post-install DLL repairs.
  Source ZIP v2, before binaries and measured deployment delta are retained;
  v3's driver-only incorrect test executable path failure is also preserved.
  Actual LocalSystem/Libreswan attempt v2 passed service/QtRO and real
  certificate-utility result probes, but FAILED certificate import in the
  production IKEv2 caller before native dial. No RAS acceptance is claimed.
  `windows-ikev2-credential-20261125-v7.log` then measured Qt 6.10.1's retained
  QTemporaryFile write handle producing native ERROR_SHARING_VIOLATION (32).
  Four credential tests passed, including real read-only Win32 access to the
  new closed QFile in an owner/System-only RAII directory and final removal.
  The production import now uses that ownership model and redacts secret
  process arguments. Its updated full build/install and next native attempt
  are in progress, not yet accepted. Original failed native logs remain.
  The credential production rebuild/standard install v5 subsequently passed;
  actual RAS reached Connected. UDP/TCP A forwarding initially failed because
  the isolated peer's loopback data path bypassed outbound XFRM (measured
  outbound SA 0 packets). A /32-only repair v5 was insufficient: lo had
  disable_policy=1/disable_xfrm=1 and the container sysctls are read-only.
  An owned dummy data link and checked Libreswan updown route now preserve
  native ESP without adding host/underlay networking. Attempt v6 passed direct
  UDP/TCP AAAA NODATA and A forwarding, then failed system lookup latency.
  v9 retained DNS ETW proves the alias returned native DNS_INFO_NO_RECORDS
  within about 4.5 ms, but WinDNS's parallel Ethernet query timed out after
  about 12 seconds. Qt 6.10.1 maps that documented NODATA status to ResolverError.
  The actual-client assertion now uses exact DnsQueryEx DNS_INFO_NO_RECORDS,
  no records, bypass-cache and the original <5s latency bound; generic errors
  and timeouts are not accepted. Existing OS resolver scopes are being guarded
  separately on their original interfaces, never substituted for PPP DNS.
  The v10 production build/native acceptance for this integration is pending.
  Startup recovery now retains prepared/restored/completed phases and gates
  service shutdown on the durable recovery result, not empty new DnsUtils.
  Its Windows normal link/install v9 passed; the added actual PID-1 crash +
  external-edit + fresh-service-stop regression still needs execution.
  `windows-ikev2-os-scopes-link-20261125-v11.log` passed the corrected normal
  Windows build/standard install (v10's missing explicit QObject parent
  compile failure is retained). `windows-ikev2-production-acceptance-20261125-v11.log`
  then passed 4 actual-client tests against installed LocalSystem and real
  certificate-authenticated Libreswan: both selected OS scopes return UDP/TCP
  NODATA, negotiated PPP A forwarding works over UDP/TCP, uncached native
  system AAAA returns exact DNS_INFO_NO_RECORDS in 6 ms, and a foreign DNS edit
  holds native RAS/aliases until exact repair and confirmed restore-before-join.
  Peer DNS witnesses show 0 forwarded owned AAAA; all owned A sources are the
  negotiated 10.70.0.2 (both UDP and TCP). This is basic IKEv2-OFF acceptance,
  not ON/default, encrypted-DNS/NRPT, restart/crash or other-platform acceptance.
  `systemd-installed-startup-20261125-v22-startup-conflict.json` now passes
  the actual fresh-service recovery failure regression: crash after external
  DNS edit, automatic new PID, stop holds that PID in deactivating, exact
  repair, confirmed DNS/alias restore and successful exit with no journals.
  Windows installer pre-payload barriers now share one reviewed PowerShell
  source embedded into CMD/IFW/MSI at configure time (no new runtime helper).
  MSI disables Restart Manager and schedules a deferred checked stop/join
  before StopServices/RemoveFiles; IFW queues it before default Extract.
  Normal Windows build/install v12 and v15 passed. Production MSI packaging
  v13 failed because CPack forbids duplicate #PRODUCT fragments; that failure
  is retained and the fragment was consolidated with the existing close-app
  patch. Corrected production packaging and >30s actual-installer SCM join
  acceptance are pending, not claimed as native RAS installer acceptance.
  `windows-installer-stop-packaging-20261125-v15.log` built both actual MSI
  (62bf12e2d18650f1a005a2c3e8423fa2aa1c80abafd23cfab2b9eb449e111232)
  and IFW (f44f04d91105dd75b2e40aec34f7a30b6eb0a563ed38b707353d121de8a46c84).
  Actual MSI uninstall v17 and IFW purge v19 retained the same pending SCM PID
  and unchanged production service/Go DLL bytes for 35 seconds, then completed
  after the test-only external join release. These are installer/SCM sequencing
  cases, not invented native RAS or physical-device results. v16's existing
  empty default-directory refusal and v18's driver ExitCode-null failure remain.
  The v18 actual install log also exposed concurrent IFW Extract preceding
  queued Execute. The pre-payload gate is now synchronous in createOperations;
  its new package/pre-extract runtime acceptance remains pending.
  Actual native defaults v20 passed 6 cases: missing legacy setting and
  explicit ON retain original negotiated DNS and positive upstream UDP/TCP
  AAAA, while OFF returns local NODATA (system native lookup 3 ms) and never
  forwards the owned OFF AAAA. Cleanup logs revealed the legacy ON stop's
  stale handle/blind 3s sleep; it now awaits documented invalid-handle join,
  clears the handle, and has an explicit repeated-stop assertion. v22 is pending.
  Native v22 then passed 6 cases with joined/idempotent ON stop and no stale
  handle errors. Actual IFW pre-extract v25 retained 0 extracted binaries and
  the same pending PID for 35s; after the owned old-definition transition it
  installed normally and completed normal maintenance purge. v24's driver
  race (deleting the SCM definition during the gate's final query) is retained.
  `windows-dns-policy-security-20261125-v31.log` passed seven actual native
  reader states (21 QtTest assertions including setup/cleanup): plain defaults,
  selected global DoH auto-upgrade refusal/repair, effective NRPT DNSSEC
  refusal/repair, Require-DoH refusal/repair, without changing adapter DNS.
  This reader is now in production durable capture/restore and guard health,
  with original resolver/alias policy metadata retained and no plaintext
  downgrade of unsupported DoH/profile/namespace policy. It is not encrypted
  DNS forwarding support. Normal build/install v32 and v33 passed; actual
  LocalSystem/client/Libreswan v33 passed 7 cases (system NODATA 32ms).
  Actual-client DoH and NRPT refusal v34 each passed 3 cases, with native IKE
  establishment count unchanged at 13 before/after both refused attempts.
  IPv6-only OS-scope attempt v35 failed in driver preflight reading an absent
  registry value, before DNS mutation/service registration; no acceptance.
  Review additionally found that pending restore must quiesce upstream DNS
  while retaining NODATA listeners. The existing Go runtime/C ABI now has a
  separate cancel/join quiesce boundary (no new helper/dependencies).
  Portable race v36 passed 12 cases with 2 explicit interface-fixture skips;
  owned Linux native-interface race v37 passed all 14 with no skips, including
  active-exchange join, retained UDP/TCP NODATA and post-quiesce SERVFAIL.
  Actual archive/C ABI rebuild v37 failed before compile because the selected
  module-cache root lacked the frozen Xray core. Cached-source discovery and
  Linux/Windows runtime rebuilds are pending; new quiesce ABI is not yet
  accepted in production backend runtime. Windows VM/peer were shut down only
  after confirmed service/native cleanup, freeing aggregate local resources.
  Corrected-cache v38 then rebuilt the existing Xray archive offline with
  unchanged compiled dependency versions and passed the actual C ABI fixture
  (including repeated quiesce, retained UDP/TCP listeners and stale handles).
  C++ transaction v38 built and passed CTest 1/1 (0.28s), including a new
  exact quiesce-before-restore/failure/foreign-owner regression. Production
  Linux service relink against that measured archive is running; this is not
  yet backend acceptance of the new boundary.
  Production Linux service v38 subsequently linked successfully (54 Ninja
  steps, current archive/header). Service fixture v39 compiled successfully
  but its first driver invocation omitted the required read-only `/host/usr`
  mount and stopped before starting private resolved. Corrected v40 passed
  2/2 CTest suites against actual private systemd-resolved: 15 transaction
  cases and 15 service cases, with one explicit child-only fixture skip.
  Full Xray/QtRO and Windows production acceptance of quiesce remain open.
  Installed-layout Linux Xray/QtRO v43 then passed actual failed-restore
  retention and repair/retry cleanup (service SHA256
  `02348b1a99b5dc0525e3a9378f6e378b4271e1672d79efb9c7d9d619feaaccc8`).
  v42 is retained as a driver-path failure before service startup: installed
  binaries are under `bin/`, not the install prefix itself. Go native race
  v41 passed all 15 cases, including concurrent admission/quiesce/Close.
  Additional immediate-quiesce handling for reused failed publication and
  guard-watch failure passed C++ transaction v44 (16 cases). Windows v45
  rebuilt/export-checked the actual DLL offline; production link failed
  because its driver leaked the Xray-only module cache into the independent
  frozen routing build. Corrected-environment link v47 is running; no package
  download or dependency version change is authorized. A test-only selected
  DoH mutation branch has been added but is not yet built/executed.
  Windows v47 full normal build/install passed with the existing default
  routing module cache; actual quiesce DLL SHA256 is
  `1f718e4d3d83f4390f499b540b0c7b91b623911a83ac0bc2f91914cf951c9ed2`.
  The v20 peer intentionally refuses restart into its existing evidence path;
  that failed preflight is retained. A fresh isolated v50 peer generated new
  explicitly named certificates/source manifest, staged only under v50 names.
  v48 compiled the test-only policy-mutation branch. Aggregate native v46
  FAILED (6 passed, 1 failed): its first OFF admission disconnected before
  Connected, whereas both ON/default rows and the later native OFF lifecycle
  passed (system NODATA 11ms). It is not accepted as a successful aggregate.
  Exact RAS events report a first failure with error 0 and the peer records no
  first IKE SA; its subsequent three IKE sessions are separately witnessed.
  Numeric RAS callback/terminal diagnostics were added, without changing native
  admission, assertions or timeout. v52 diagnostic rebuild is pending; policy
  mutation v49 and IPv6-only side-scope execution have not run.
  v52 diagnostic full build/install passed. v53 targeted diagnostic reproduced
  the first-admission failure (2 passed, 1 failed); actual callback transitions
  0..5 end at RAS state8193/error628, whereas the RAS event log misleadingly
  reports error0. Current/baseline Windows DLL compiled dependency/version/
  checksum lines compare exactly equal. IKE/RAS channel inspection is retained.
  Admission-reply and explicit-stop ordering diagnostics are now added; the
  instrumented v55 build/v56 run are in progress, not an acceptance rerun.
  v55 normal build/install and v56 diagnostic then passed (3 QtTest cases);
  the admission ACK had `stop already requested=false`, followed by Connected
  and a requested joined stop. This does not causally resolve v46/v53's
  first-admission failures: diagnostics changed timing, not native behavior.
  Policy-mutation v49 and IPv6-only side-scope v40 are now executing against
  the explicitly recorded installed v52 candidate and v50 peer.
  Mutation v49 FAILED after successful native connect/NODATA (5ms): one
  still-published OS-scope A query timed out instead of returning SERVFAIL.
  Cleanup repaired the exact owned DoH mapping and confirmed Disconnected;
  the sequential driver stopped, so IPv6-only scope v40 did not execute.
  The production cause is in WindowsIkev2Dns::restoreDns: refusal restoring
  PPP returned before quiescing the separate existing OS scopes. An explicit
  owner-checked DnsUtils quiesce operation now allows all scopes to cancel/join
  before any restoration is attempted. v57 current normal build/install is
  running, v58 retains the identical failed mutation assertions, and a new
  portable two-scope transaction regression awaits execution.
  v57 normal build/install passed; identical actual policy-mutation v58
  passed all 3 cases (system NODATA 8ms): PPP and existing OS aliases retain
  UDP/TCP NODATA and return A SERVFAIL while policy blocks restoration, then
  exact DoH repair allows confirmed native join/retirement. The cumulative
  peer witness has one pre-observation polling A query for the mutation label
  and zero owned OFF AAAA; it is not evidence of zero queries before quiesce.
  IPv6-only v40 refused its actual OS precondition before service start:
  setting a v6 DNS server did not remove DHCP's v4 DNS. Exact baseline reset
  was attempted in its cleanup. v60 explicitly clears the owned IPv4 DNS list
  with native netsh before selecting v6 and rechecks both families; it is
  running. Diagnostic v59 retained a separate unsupported PowerShell parameter
  failure. Additional continue-on-quiesce-error handling and two portable
  transaction regressions are newer than the v57 installed source and still
  await build/execution.
  v60's recorded OS selection still contained DHCP IPv4 `10.0.2.3` together
  with v6 `2001:db8::53`; exact reset matched its baseline. No IPv6-only
  acceptance was inferred. Rather than disabling DHCP/changing the VM control
  link, the native client fixture now creates an owned Wintun data link with
  a checked v6-only DNS list, retaining the original Ethernet scope unchanged.
  Native transaction v61 passed all 18 cases under actual MSVC/Qt (318ms),
  including all-scopes quiesce and continue-on-failure across generations;
  normal full production build/install v61 also passed.
  The new test-only Wintun branch initially failed MSVC compilation in v62/v64
  due to missing ordered Windows networking headers. Source now uses the
  established winsock2/ws2tcpip/iphlpapi/netioapi ordering; v65 build and v63
  owned-link acceptance are running. No production dependency/helper added.
  v65 MSVC test compile/link passed. Owned-link v63 then correctly refused
  its precondition before native dial, revealing that the test helper itself
  enumerated AF_INET-only DNS. It now enumerates AF_UNSPEC and decodes checked
  IPv4/IPv6 socket addresses, including native IPv6 scope IDs; the exact
  v6-only expected list is unchanged. v66 compile and v67 owned-link run are
  in progress. v63 failure evidence and exact source deltas are retained.
  v66 test compilation passed; v67 satisfied the real v6-only OS-link
  precondition but reproduced the native admission failure. Its service trace
  gives the causal boundary: `RasGetConnectStatus` returned INVALID_HANDLE at
  callback state0, then RAS continued states1..6. That early invalid handle
  caused premature service cleanup, not a remote rejection. The adapter now
  uses instance-scoped RasDialFunc2 terminal notifications and retains Pending
  before a settled dial; no sleeps or timeout relaxation. A durable
  `dial-returned` phase preserves crash uncertainty before native-handle proof.
  Cancellation/normal stop still require native invalid-handle join after
  observed handle/terminal failure, not the pre-registration window.
  v69 stopped on a source-hash guard (header baseline came from v10, not v2),
  after applying the checked .cpp; no native test ran. The retained v71 header
  delta resumes that exact partial state, then full build/install and v70
  owned-link acceptance. Further conservative post-notification invalid-handle
  checks are newer than that staged delta and still require rebuild/measurement.
  v71 normal full build/install passed. Actual owned v6-only Wintun DNS
  scope v70 passed all 3 cases: checked native selected DNS list, UDP/TCP
  NODATA and non-AAAA SERVFAIL without PPP substitution, PPP A forwarding,
  system NODATA 9ms, foreign-edit retention and exact retirement. Cumulative
  peer witness records zero v6-scope A queries and zero owned OFF AAAA.
  v72 compiled the additional join proof changes, but aggregate v73 FAILED
  (3 passed, 4 failed): first OFF connected, then stop remained pending.
  The added repeated RasHangUp after invalid status returned 668 instead of
  success/invalid-handle and prevented the already-joined lifecycle retiring.
  Current source skips that duplicate call after a successful hangup.
  Exact native MSVC probe v76 measured saved handle720896 status6
  (ERROR_INVALID_HANDLE), native enumeration success/count0, original Ethernet
  DNS `[10.0.2.3]`/empty v6, with no native PPP/managed aliases observed.
  Old candidate v72 PID512 remains SCM STOP_PENDING, retained with journals,
  VM and peer; it is not killed or reported as a successful service stop.
  Corrected candidate v77 is building/installing into a separate prefix.
  Native acceptance of v77 cannot replace that live pending old definition
  without resolving its immutable in-process join loop. The prepared v74/v75
  GUI-process-loss fixture has not run; Windows Go race v68 did not execute
  because the sequential driver stopped on failed v73.
  Corrected full build/install v77 passed offline into its separate prefix;
  old v72 PID512 and its payload remain untouched. Runtime v77 acceptance is
  concretely blocked by the retained old STOP_PENDING process: its immutable
  duplicate-hangup loop cannot consume the already-measured native join proof.
  A scoped user decision is required before any exception to the prohibition
  on terminating pending cleanup. No force-kill, reboot, journal deletion,
  protection bypass, intermediate push, CI dispatch or merge was performed.
  2026-11-26: user explicitly approved the one-time exact old PID512 exception.
  v78 rechecked executable/SCM/owner identity, exact saved-handle status6,
  native count0 and restored underlay DNS, archived old journals/logs, then
  terminated only that held process handle. Corrected production v77 startup
  recovered the preserved hangup-requested journal into a completed receipt;
  its subsequent normal SCM stop and process join passed. Old journals were
  not manually deleted or relabeled as a successful v72 stop. v79 full native
  suite, compiled v74 lifecycle gate/v75 GUI loss, and Windows race v68 are
  now queued sequentially. Aggregate active fixture limits were measured again:
  Windows wrapper 1.5CPU/3.5GiB plus peer 0.5CPU/512MiB, zero extra swap.
  v79 current production native suite passed 7/7 (system NODATA 16ms);
  v75 actual test-GUI process loss retained the same LocalSystem/RAS owner
  and UDP/TCP NODATA, then normal SCM stop restored original DNS and joined
  native cleanup. Windows Go race v68 passed 13 portable/socket cases with
  no skips (1.747s); Linux-only native-link fixtures are not in that build.
  v80 intentional crash of the checked Running service preserved journals;
  fresh production startup restored DNS/aliases, joined RAS, delivered caller
  Disconnected, and completed a subsequent normal SCM/process join (3 cases,
  system NODATA 4ms). This is recovery acceptance, not continuous protection
  during downtime. Review found dynamic WFP policy lifetime warrants an actual
  traffic check: v81 adds a real IPv6 positive control, active-OFF block and
  pre-restart crash-downtime witness, while still completing recovery before
  reporting any enforcement failure. That experiment is running.
  v81 completed native recovery but FAILED continuous OFF enforcement:
  the real IPv6 UDP positive control was blocked during the live connection
  and delivered again after the service crash, before recovery. The dynamic
  IPv6 WFP session lifetime is the measured cause. The policy now uses two
  stable-key non-dynamic kernel filters, validates owned definitions before
  adoption/removal, and has no privileged IPv6 endpoint permits. It is not a
  new runtime/helper and is not yet a reboot-persistence claim.
  v82/v84 normal full builds passed; v83/v85 refused native admission.
  Exact native status2150760494 (0x8032002e) is Microsoft's documented
  FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER: the ownership marker used rawContext,
  which this ALE layer rejects. The marker is now opaque providerData instead;
  lookup/ownership checks remain strict. Integration also denies IPC policy
  release before confirmed startup recovery and explicitly retires kernel
  policy after all native resources/processes join on normal service shutdown.
  v86 build/v87 traffic/crash/cleanup acceptance are in progress. The new
  strict IPv6 endpoint-exception positive/negative control test is not yet
  staged or executed; no new pass claim for these pending changes.
  v86 normal full build/install passed. v87 actual crash-fence acceptance
  passed all 3 native-client cases plus four real traffic phases: IPv6 UDP
  positive control, active OFF block, crash-downtime block with the service
  absent, and restored IPv6 delivery after confirmed recovery/SCM cleanup.
  Native DNS/caller/journal retirement and original underlay DNS restoration
  also passed (system NODATA 8ms). This closes the measured service-process
  lifetime leak for the exercised Windows IKEv2/UDP witness, not reboot or
  other-platform acceptance. v88 stages the new explicit IPv6-endpoint
  exception test, followed by the changed-policy full native suite v89.
  v88 compiled the explicit IPv6 endpoint-exception test; v89 current native
  suite passed 8/8, no skips, including that traffic positive/negative control
  (system NODATA 7ms). v90 generated current production MSI and IFW packages.
  v91 MSI and v92 IFW actual installed LocalSystem/native-RAS acceptance both
  passed: external PPP DNS mutation held the same service PID and unchanged
  service/runtime payload for 35 seconds, with UDP/TCP AAAA NODATA and A
  SERVFAIL throughout refused restore. Exact DNS repair then allowed native
  process join and uninstall/purge with no owned RAS/alias state remaining.
  These used production payloads, not the earlier test-only SCM fixture.
  MSI SHA256 9888d4d7a30f6228180f0a1cdb908956c1eec9e66e1aad3f1069e56c6fd3f14c;
  IFW SHA256 2595044509bca4cae24057b4cbe1de5925562a1101bf42817515c34471a1a46c.
  Current service SHA256 d4b8a6223026c89aec44862d68a7f0693410b719b8028a1359761bad9ac1d7e2.
  v93 repeats actual DoH mutation/quiesce acceptance on this kernel-policy
  candidate passed 3/3, no skips (system NODATA 10ms); the injected policy
  mutation produced the expected helper error and confirmed native cleanup.
  Platform/backend gaps and final CI remain open.
  v94 current owned IPv6-only DNS scope acceptance passed 3/3, no skips,
  system NODATA 5ms.
  Additional Windows WG shutdown ordering review remains open: generic kernel
  policy retirement currently precedes the aboutToQuit daemon deactivation,
  and WindowsTunnelService::stop discards stopAndDeleteTunnelService failure.
  IKEv2 package acceptance above does not establish WG native join ordering;
  this path needs failure propagation and measured acceptance before closure.
  Pending WG implementation now preserves a failed tunnel-service stop for
  retry, avoids repeated STOP controls while STOP_PENDING, restores DNS before
  retiring peers/interfaces, and gates generic Windows kernel-policy release
  on daemon deactivation. v95 build is running; a follow-up removes the
  interface-absent fallback as Windows worker-join evidence and is not yet
  staged. These changes are not covered by prior IKEv2 acceptance.
  v95 and v96 actual MSVC full client/service builds and normal installs
  completed. v96 includes the Windows-specific removal of interface-absent
  fallback; v97 runs the native IKEv2 regression suite on that candidate.
  Actual WG stop-failure/SCM-worker join acceptance remains outstanding;
  successful compilation is not evidence of that lifecycle behavior.
  v97 native IKEv2 regression passed 8/8, no skips, system NODATA 35ms.
  v98 exercises actual WG native tunnel-service creation/publication, refused
  DNS restoration for 35 seconds and subsequent service/worker process join.
  It deliberately does not assert a WG handshake or peer data-plane delivery;
  v98 FAILED before the hold boundary: WG address/managed DNS publication did
  not appear within 30 seconds. Normal service cleanup completed, and v99
  inventory found no remaining Amnezia SCM definitions. Captured log contained
  earlier IKEv2 entries rather than this activation. v100 adds explicit
  service logging initialization and captures the activation pipe response
  to diagnose the failure, preserving the same lifecycle assertions.
  v100 established the admission cause: deployed tunnel.dll rejects
  "amnezianativedns" as an unknown Interface key (native error1066).
  The recipe already contains a checked native-DNS ownership overlay, but
  this deployed cached binary does not implement it. Do not remove the key
  or treat that binary as current WG acceptance. v104 found cached AWG
  v3.1.20260814 sources and dependency module cache; offline toolchain/build
  discovery is in progress. Local overlay regression ran 4 tests, all passed;
  these source-transform tests are not native WG runtime acceptance.
  v105 located cached MinGW and Go toolchains. v106 is building a new DLL
  from a preserved copy of cached native AWG sources with the current checked
  overlay, GOPROXY=off/GOTOOLCHAIN=local and two Go workers. Existing source,
  binaries and failed evidence are not overwritten. Deployment/provenance,
  actual WG lifecycle and package closure remain pending this build.
  v106 offline DLL build passed, SHA256
  29dccaf27a107b0aeb567327e6bad9070ea47e3b14f4e34a39eca17feb471615.
  Compiled module versions/checksums and source-before/after manifests are
  retained. v109 selects the new artifact through a separate frozen AWG
  CMake target and normal build/install into a new prefix; it does not mutate
  old Conan cache binaries or copy over an already installed payload.
  This is a checked-overlay cached-source build, not a new Conan recipe-run
  claim. v110 is prepared to exercise the unchanged WG lifecycle assertions
  only after installed DLL identity matches that new artifact.
  v109 normal CMake configure/build/install completed; installed tunnel.dll
  matched v106 exactly. Service SHA256
  d9f9c12fcab3602f6c0b5bacec78cc146a4347d0095f0405c159c04c6047cf5c.
  v110 actual WG lifecycle acceptance is running on this prefix. v90 package
  evidence remains valid only for its recorded payload/IKEv2 scope, not for
  current native-DNS WG support; new package generation/audit is required.
  v110 FAILED: final cleanup timed out and left exact main service PID3960
  STOP_PENDING. v111/v112 measured the WG child service Stopped/PID0, only the
  main AmneziaVPN-service.exe process remaining, original Ethernet DNS
  10.0.2.3, no WG/managed alias addresses and no native-dns journal files.
  The main process loops on DeleteService ERROR_SERVICE_MARKED_FOR_DELETE
  for the already-stopped child definition. Full log and ownership/network/
  journal inventory are preserved under windows-wg-pending-preserved-v112.
  Repeated deletion is now idempotent for that exact native error after a
  confirmed stopped service status; other errors still retain ownership.
  v113 builds/installs this candidate into a separate prefix, leaving PID3960
  and its original payload untouched. Runtime deployment is blocked by this
  old pending owner. No process has been force-killed; the earlier PID512
  exception is exhausted and does not authorize terminating PID3960.
  v113 actual MSVC build and normal install completed successfully. Runtime
  verification of idempotent retirement remains blocked pending permission
  to retire only the preserved old PID3960; build completion is not a
  response granting that permission.
  External host/server restart then stopped the Windows wrapper (exit137)
  and peer v50 (exit0). No agent force-kill was performed or authorized.
  Wrapper restarted with its existing 1.5CPU/3.5GiB/no-extra-swap limits;
  peer remains stopped (its existing evidence directory must not be reused).
  v114 measured new Windows boot, main service Stopped/PID0, no remaining
  native worker, original 10.0.2.3 DNS and intact v113 candidate hashes.
  This is an external crash/reboot boundary, not a normal-cleanup pass.
  v115 now exercises normal candidate startup/stop/join against that retained
  SCM definition, followed by v116 actual WG lifecycle acceptance. v116 waits
  for OS DNS publication, not merely prepared aliases, and saves a primary
  failure before finally cleanup can mask it. Results pending.
  v115 normal startup/SCM stop/process join passed without force-kill.
  v116 reached actual WG DNS publication and retained main PID1780/worker1908
  behind the external DNS conflict for 35s, but FAILED worker WaitForExit.
  v117 subsequently measured service Stopped/PID0, no Amnezia service
  processes, original DNS and no WG/alias addresses. This later inventory is
  not evidence that the original bounded worker wait passed. v118 retains
  that assertion and adds an independently pinned Win32 process handle with
  an active-worker WAIT_TIMEOUT positive control plus terminal wait/exit-code
  measurements to diagnose the discrepancy. No assertions/timeouts relaxed.
  v118 FAILED with direct native evidence: main joined, worker PID1560 still
  present, pinned process WAIT_TIMEOUT(258), exit STILL_ACTIVE(259).
  This is a real process-lifetime gap, not a managed WaitForExit discrepancy.
  Entrypoint inspection found tunneldaemon falls through into LocalServer/
  app.exec after the native DLL service returns. It now returns the native
  result immediately. WindowsTunnelService also pins the worker process
  after running admission and retains its service/process handles until an
  actual WAIT_OBJECT_0, so SCM Stopped alone cannot release protection.
  v119 preserves log/network/witness evidence; its final read failed because
  no process rows produced processes.json. v120 inventories that later state
  explicitly; v121 builds the terminal-entrypoint/native-join candidate.
  No force-kill or acceptance rerun of an unchanged candidate was performed.
  v120 later inventory measured zero service executable processes; no forced
  recovery is needed. v121 source admission refused a header hash mismatch
  after staging main.cpp but before compiling. v122 captured exact current
  guest source bytes; mismatch was whitespace in the reconstructed baseline.
  v123 uses those measured baseline hashes and preflights all source entries
  before staging any change; its build/install is running. v118 remains a
  preserved failure, not a pass inferred from the later zero-process state.
  v123 actual MSVC client/service build and normal install completed.
  v124 runs the same 35s actual-WG DNS-conflict/native-handle experiment on
  the terminal-entrypoint/process-join candidate; original managed join and
  independent native WAIT_OBJECT_0 assertions both remain required.
  v124 PASSED actual WG lifecycle: same native resources retained for 35s
  behind refused DNS restore; after exact repair both managed process joins
  passed, native process wait returned0/WAIT_OBJECT_0, native exit0 and worker
  absent. No force-kill. This closes the exercised terminal-worker/SCM join
  gap, not WG handshake/data-plane acceptance. v125 generates fresh MSI/IFW
  from this configured payload (including the rebuilt native-DNS tunnel.dll).
  v126 adds UDP/TCP AAAA NODATA and A SERVFAIL on every owned alias during
  the held WG restore boundary; prepared, not yet executed.
  v125 generated both fresh production packages successfully:
  MSI af056d4cccfe3eae655d74651f367686c555f7f9d08187d8ba24685681d76105,
  IFW 12a496c053850e11c306a252a319d2995ddb2e126ee1b560daec9b48b67a84be.
  Packaged service SHA256
  28aff0b5fb52d017542a24552212e751772e803c43b2da65213f51bafc51353a.
  v126 held-WG UDP/TCP DNS acceptance is now running. v127 is prepared to
  check exact WG/Xray/service hashes in both CPack payload trees; new actual
  installer runtime acceptance remains outstanding.
  v126 PASSED held native-WG DNS acceptance: UDP/TCP AAAA NODATA101/76ms,
  A SERVFAIL3/10ms, then both managed joins and native wait0/exit0.
  v127 checked all three exact service/WG-DLL/Xray-DLL hashes in both CPack
  payload trees, all matched. v128 actual production MSI/WG uninstall PASSED:
  same PID/service+WG DLL payload retained35s, UDP/TCP NODATA66/48ms and
  SERVFAIL4/4ms, followed by main/worker native join and payload/SCM removal.
  v129 actual production IFW/WG purge is running with the same ownership,
  DNS wire and native process-handle checks. No handshake/data-plane claim.
  v129 actual production IFW/WG purge PASSED: retained PID/payload35s,
  UDP/TCP NODATA127/70ms and SERVFAIL5/6ms, managed joins true and native
  wait0/exit0, worker absent, payload/SCM retired. v130 measured idle Windows
  guest with no native processes/active services/owned addresses and original
  underlay DNS. Current Windows WG lifecycle/package scope is closed; full
  handshake/data plane and other platform/backend requirements remain open.
  After v130 idle checks, Windows wrapper stopped gracefully with no kill
  timeout; peer remained stopped. v131 offline current Linux production
  service build passed, including common daemon.cpp and IPC/lifecycle TUs.
  Only the Linux regression container was active, measured configured limits
  2CPU/4GiB/zero-extra-swap. v132 now builds/runs current native transaction
  and real private-resolved service tests against the preserved v38 archive;
  this is not yet native Linux WG backend acceptance.
  v132 current native transaction tests passed18/18, no skips; compilation
  targets (including common WG daemon TU) passed. Service launch failed on
  non-executable wrapper permissions in the read-only source mount.
  v133 invoked the wrapper through sh, started real private resolved/D-Bus,
  but service init failed because the required dns-fixture/192.0.2.10 native
  link was missing. Both harness failures are preserved, not backend passes.
  v134 supplies that owned dummy link before running only the outstanding
  service suite; completed transaction tests/builds are not repeated.
  v134 real private-resolved service suite passed15, failed0, skipped1
  (expected child-only fixture; parent crash-recovery cases passed).
  Common teardown review found run(Down), including application-split
  retirement, still preceded DNS restore. v135 focused fake-adapter tests
  measured two ordering failures (3passed/2failed). DNS confirmation now
  precedes platform Down, peer/routes/interface retirement and acknowledgment.
  v136 green focused suite passed6/6, no skips, including refused-DNS and
  platform/interface failure retention/retry; v137 current Linux production
  service compiled/linked successfully. These tests are not native backend
  acceptance. Windows v138 production build/install and v139 actual-MSVC
  focused regression are next; earlier v125 packages predate this ordering
  change and cannot be relabeled as the final current-source artifacts.
  v138 actual Windows production build/install passed. v139 focused MSVC
  test build FAILED before compilation: Ninja's manifest remained dirty after
  100 CMake regenerations. v140 measured extracted CMakeLists timestamp
  13:46UTC versus guest10:53UTC/build.ninja10:52UTC (ZIP metadata/time-zone
  mismatch). v141 uses the same hash-checked archive in a new staging prefix,
  normalizes only source timestamps to guest time and rechecks every file's
  bytes; regeneration remains enabled. Focused Windows test result pending.
  v141 actual-MSVC focused lifecycle suite passed6/6, no skips. Together with
  v135 red/v136 green this measures common teardown ordering without claiming
  native application-split driver acceptance. v142 runs current real WG
  publication/35s-held UDP+TCP DNS/native-join regression on v138, followed by
  v143 fresh current-source MSI/IFW generation if acceptance succeeds.
  v142 current real WG regression PASSED:35s refused restore, UDP/TCP
  NODATA76/57ms and SERVFAIL4/6ms, then managed/native worker joins with
  wait0/exit0. v143 current production MSI/IFW generation succeeded:
  MSI efe8ac23028a8e4ee9ce3d777bcacfb8f89762d4036693a7c5ab2afffb96495d,
  IFW be16c33302a0b5226fee6e1cd328e3287e7e4aa39949a833fd244ff5d5faa27f,
  service6619ab1bc98036870069ac95909c417bf9004e2271d00fd6f3ae504486e052e9.
  v144/v145 execute actual MSI/IFW native-WG retained-cleanup acceptance
  on these exact payloads. Earlier package evidence remains historical.
  v144 MSI and v145 IFW actual current-source native-WG installer acceptance
  both PASSED35s retained PID/payload plus managed/native worker joins:
  MSI UDP/TCP NODATA130/93ms, SERVFAIL9/7ms;
  IFW UDP/TCP NODATA63/53ms, SERVFAIL3/5ms; wait0/exit0, worker absent.
  v146 discovered existing cached disposable WG peer support. v148 runs
  that fixture (binary SHA256
  e41328f921f91c856115ce93b1d293bba120bc65660e43411f3a51132e8fe92f)
  in the Windows wrapper's isolated network namespace,0.5CPU/512MiB/no
  extra swap, aggregate with Windows1.5CPU/3.5GiB remains2CPU/4GiB.
  Disposable client keys stay private and v147 transfers them only through
  authenticated encrypted WinRM, never source/evidence/public HTTP.
  v149 now checks real native WG TCP/UDP peer delivery and an actual IPv6
  positive-control/OFF-block witness before the held-cleanup assertions.
  Result pending; earlier no-handshake lifecycle passes are not relabeled.
  v149 FAILED strict OFF while real native WG handshake/TCP/UDP delivery
  passed: actual IPv6 witness delivered before AND during OFF. Native Windows
  WG adapter never applied the independent kernel policy from the raw switch.
  It now applies it before interface creation and releases only after joined
  tunnel-worker cleanup; KillSwitch remains optional and IPv4 unaffected.
  Route-monitor retirement also follows joined worker cleanup.
  v150 actual production build/install passed. v151 real native WG acceptance
  PASSED: IPv6 positive before, blocked during OFF, restored after join;
  authenticated native TCP/UDP peer echoes, actual IPv4 DNS forwarding,
  active UDP/TCP AAAA NODATA,35s held restore with NODATA24/6ms and
  SERVFAIL4/6ms, managed/native wait0/exit0 and policy retirement.
  v152 tests missing/default ON and explicit ON on this candidate with native
  IPv4+IPv6 peer TCP, positive UDP AAAA and unchanged native DNS/no aliases.
  Earlier v143 package acceptance predates the native-WG OFF enforcement fix.
  v152 ON/default TCP connect FAILED; cleanup joined. v153 retained error
  context but logging was still historical. v154 enabled current logging,
  required native status/handshake and IPv6 Preferred, and measured actual
  cause: IPv4 remained Tentative and connect to10.77.0.2 failed unreachable
  while both final routes were present. v155 requires Preferred for both
  families within the unchanged30s readiness deadline. DAD is not disabled,
  test assertions are not weakened; ON/default acceptance remains pending.
  v155 missing-setting ON passed native IPv4/IPv6 TCP, positive UDP AAAA
  and unchanged native DNS/no aliases, but FAILED the final executable-name
  process-absence guard after successful main join. v156 later CIM inventory
  measured zero live processes; that later absence is not an acceptance pass.
  v157 pins/joins the actual WG worker separately, records executable-name
  observers with Id/HasExited, rejects any live row, releases joined observer
  handles and retains the zero-process assertion before SCM retirement.
  This diagnoses observer-held exited-process objects without force-kill or
  weakening native join; both ON variants remain pending this experiment.
  v157 both missing/default ON and explicit ON passed native IPv4/IPv6 TCP,
  positive AAAA/native DNS/no aliases and separate managed worker joins, but
  final name-only guard still failed. v158 read saved rows: Id1848 and3812,
  each HasExited=true; current CIM live count0. v159 adds pinned Win32
  WAIT_TIMEOUT active-worker control and WAIT_OBJECT_0 for owner/worker,
  accepting only known already-joined exited observer objects while rejecting
  any unknown/live process. This corrects observer semantics, not the native
  join contract; final ON/default acceptance remains pending v159.
  v159 PASSED both missing/default ON and explicit ON: native DNS10.77.0.2,
  no aliases, positive UDP AAAA, authenticated native IPv4+IPv6 TCP delivery,
  pinned owner/worker WAIT_OBJECT_0 and zero live native processes after stop.
  v160 generates new current-source MSI/IFW packages including strict native
  WG OFF enforcement; final package identity/runtime acceptance is pending.
  v160 generated current strict-WG packages:
  MSI d1a2e07de1253f28a4c162e6ad991e67ee6d98a91bf32ed94935a0796560cd46,
  IFW 66bd844938ce2182356aa8d48d6e596398b72ebd5b4731166a306e960ad5b82c,
  service e398fa17758fac78e83825106d79d281d43bf3571336f1d6f670ef7f918e6a62.
  v161/v162 actual MSI/IFW35s-held native-WG cleanup acceptance is running
  against those exact hashes. Earlier pre-enforcement package results remain
  historical; no final CI, push or merge has been performed.
  v161 current MSI and v162 current IFW actual native-WG installer acceptance
  PASSED35s retained PID/payload and managed/native wait0/exit0:
  MSI UDP/TCP NODATA112/97ms,SERVFAIL3/5ms;
  IFW UDP/TCP NODATA84/71ms,SERVFAIL4/15ms; no remaining worker.
  v163 now exercises deliberate ACTIVE-service crash (not pending cleanup)
  during a real WG peer connection, preserving the pre-crash journal and
  measuring worker retention/IPv6 block while the main service is absent.
  Recovery runs even if enforcement fails, and must restore DNS/aliases,
  join the old native worker and complete normal fresh-owner SCM stop.
  v163 FAILED recovery and preserved fresh main PID3616 STOP_PENDING.
  Crash witness measured old main3816 gone, native worker3820 survived and
  IPv6 stayed blocked during downtime. v164 measured only main3616 remaining,
  original underlay DNS10.0.2.3 and no WG/alias addresses, but durable owner
  431830bf-7291-41fa-8c3d-1ca91a18b329 still unresolved (adapter GUID
  05b44401-f55a-1be5-94c3-7fa54bb2d33e). Recovery cannot confirm OS DNS after
  that native adapter was removed. No force-kill or journal deletion.
  Root cause: LocalServer's WindowsDaemon value member constructs BEFORE
  the constructor body, and WindowsTunnelService stops/deletes the old WG
  worker/adapter before recoverStartupDns. WindowsDaemon is now deferred
  until durable DNS/RAS recovery confirms; unresolved startup exposes no IPC.
  Orphan worker handles are retained until native join, new WG starts first
  join any old owner, and IPC kernel-policy changes are gated on BOTH WG and
  IKEv2 ownership. v165 captured exact guest baselines; v166 builds/installs
  the checked delta into a separate prefix, leaving PID3616 untouched.
  Runtime verification is blocked by the preserved missing-adapter journal;
  it must not be bypassed by deleting/relabeling state or killing cleanup.
  v166 actual MSVC client/service build and normal install completed.
  Runtime acceptance remains blocked by old PID3616 and its missing-adapter
  journal. Next proposed fixture repair is to restore only the original
  test-owned WG adapter from the preserved private configuration, retaining
  GUID/security/DNS comparison and the journal until normal recovery confirms.
  This repair has NOT been executed; no permission to force-kill pending
  cleanup has been inferred from the active-crash experiment.
  User explicitly approved restoring only the original test-owned WG adapter
  from preserved private configuration, with GUID/DNS checks and without
  journal deletion or force-kill. v167 rechecks exact PID3616/executable,
  durable owner/GUID and private fixture hash, then starts only that original
  native adapter without peers/DNS publication. Its own service recovery must
  retire the journal and join PID3616; only then may the repair worker stop
  and join. On uncertainty the repair link/owner is retained. v167 running.
  v167 did not create a service: sc.exe rejected multiline binPath arguments.
  v168 used the SCM-backed New-Service API instead; definition creation
  succeeded but Start-Service failed. Neither attempt edited the DNS journal
  or terminated PID3616. v170 reads native exit codes and redacted DLL ring
  messages to diagnose admission; exact candidate hashes are captured by169.
  v170 measured original main SCM Stopped/PID0/exit0: the briefly recreated
  adapter enabled its normal pending recovery, although the repair child then
  failed native firewall setup1066/specific6 (missing service-SID group).
  v168 remains a startup failure. Independent v171 postconditions PASSED:
  original PID3616 normal exit0, zero live native processes/active journals/
  WG addresses/aliases, empty static NameServer in BOTH original GUID registry
  keys, original underlay DNS10.0.2.3. No manual journal edits or force-kill.
  Confirmed stopped test SCM definitions were retired normally.
  Current v166 service SHA256
  b8a797bbc115f5abff27737cfbe9d162fdb4fbd82ce1843919b6aedc25b679ac;
  WG DLL29dccaf2...b471615 and Xray DLL1f718e4d...51c9ed2 unchanged.
  v172 now executes the same real-WG active-crash/fence/recovery assertions
  on the deferred-startup/native-ownership candidate, with primary failures
  preserved before finally cleanup. Runtime result pending.
  v172 PASSED actual native WG active-crash/recovery on v166: old main3208
  crashed while worker3836 survived; IPv6 delivery during service downtime
  remained false. Fresh startup restored DNS/aliases before retiring the
  adapter, joined the old native worker, and completed normal SCM cleanup.
  Raw/log evidence: windows-wg-startup-order-crash-20261126-v172.
  v173 stopped before build: production staging does not contain lifecycle
  tests. Failure retained. v174 transfers current focused tests/daemon/shared
  sources separately (archive SHA256
  66cb408482a538aa885ddf8c0b8ca5e8e97878d31df0bd2dd6e45e2c13bb5546),
  checks the archive, normalizes only extracted timestamps with byte checks,
  and builds/runs MSVC lifecycle plus DNS transaction regressions. No change
  to production payload; result pending, not native backend acceptance.
  v174 actual MSVC19.44 current-source build and ctest PASSED2/2:
  NativeDnsTransaction0.41s, DaemonLifecycle0.08s; total0.50s.
  This is focused regression evidence, separate from v172 native acceptance.
  v175 now builds current production MSI/IFW using cached tools, after
  requiring the packaging build service hash to match accepted v166.
  Earlier v160 installer acceptance does not cover the later startup-order
  fix; new packages require their own held-cleanup installer acceptance.
  v175 MSI/IFW generated successfully, both staged service hashes match v166.
  MSI SHA2560e89a5473a94317e014cdcd9359d3cea3f6b35dace8fce3c074b5a57776db926;
  IFW SHA256188e55148d29d51dd15fb296849085dd01fcb277558a7cbfae2227d31b9f9cfb.
  Deployment warnings (dxcompiler/dxil lookup and VCINSTALLDIR) are retained
  in the log, not treated as proof of runtime completeness.
  v176 current MSI held-DNS/native-join acceptance running; v177 IFW driver
  prepared with exact new package/service hashes, to execute sequentially.
  v176 actual current MSI/WG held-cleanup acceptance PASSED: same PID/payload
  retained35s, UDP/TCP AAAA NODATA226/160ms, A SERVFAIL6/7ms; managed owner
  and native worker3984 joined, native wait0/exit0, no remaining worker before
  removal. This installer fixture makes no handshake/data-plane claim.
  Expected DNS-conflict restore warnings and route deletion error87 are
  retained in the log; later normal cleanup/join completed. v177 IFW running.
  v177 current IFW/WG installer acceptance PASSED: retained PID/payload35s,
  UDP/TCP AAAA NODATA95/80ms and A SERVFAIL2/7ms; managed owner and native
  worker2744 joined, native wait0/exit0, worker absent before purge.
  Current v175 MSI and IFW both cover the accepted v166 startup-order fix.
  v178 Android source discovery recovered existing OpenVPN3 and libXray
  sources from read-only amnezia-connection-recovery-full-build Conan cache,
  using a CREATED/never-started audit container (no added running resources,
  downloads or emulator). Source hashes recorded in
  android-native-source-audit-20261126-v178.json.
  Android OpenVPN transfers the published final TUN fd directly to native
  OpenVPN3; existing TunIO owns its reader and must remain sole reader.
  Android Xray uses existing libXray/amnezia-tun2socks engine, not desktop
  bindings. Its frozen go.mod/go.sum are preserved as audit baselines.
  Next integration work must target these actual native owners, not install
  a parallel TUN reader/runtime or treat Kotlin DNS builder changes as packet
  interception. No Android native DNS completion/runtime acceptance claimed.
  Android continuation v180 implements nativedns.Flows: DNS-only native flow
  admission, no TUN reader/device, one prepared UDP/TCP endpoint per resolver
  occurrence, immutable UDP destination, original scoped Dial forwarding,
  IPv6 fail-closed, quiesce-before-retirement and joined client closure.
  Actual cached Windows Go race run PASSED16/16 (2.094s), including three new
  flow tests and all thirteen existing resolver/socket/session tests.
  This is portable behavior evidence, NOT Android backend acceptance.
  v181 checked libXray/tun2socks overlay now decorates the existing native
  proxy (no new reader/stack/full-flow migration), exports prepare/cancel
  ownership, keeps the socket IPv6 fence until next connection, and adds
  contextual SOCKS UDP-associate/TCP-handshake cancellation. Native DNS
  upstreams use the original native proxy, never an OS/default dialer.
  The Conan recipe exports/applies this overlay and uses readonly module
  resolution instead of tidy. Native requirement declarations/go.sum are
  unchanged; only a private patched copy of the SAME tun2socks version is
  locally replaced. Three actual-source overlay tests PASSED; Python syntax
  compilation passed. Runtime adapter tests added, not yet executed.
  v182 Android arm64 parent-graph compile FAILED with CGO disabled because
  x/mobile/asset requires openAsset. Failure retained; v183 retries the same
  source with CGO and cached NDK27/API24, network none. No downloads/emulator.
  WG fixture peer was gracefully stopped (not killed) to free0.5CPU/512MiB
  for this compile; wrapper remains1.5CPU/3.5GiB, aggregate2CPU/4GiB/no swap.
  Kotlin publication/split-scope mapping and OpenVPN3 packet ingress/egress
  remain unfinished: native upstream proxy scope must not replace an original
  OS-bypassed split-DNS path. No Android support completion claim; no final
  push/CI/merge.
  v183 actual Android arm64 parent-graph Go+CGO/NDK27/API24 compilation
  PASSED exit0/OOMKilled=false, network none/-mod=readonly. This compiles the
  initial Flows/native adapter; it is not gomobile/AAR/device acceptance.
  v184 host executable/race harness is running against the actual adapter
  bytes (filename-only enablement on Linux) plus checked native SOCKS
  TCP/UDP-associate cancellation tests. It must not be labeled Android runtime.
  Follow-up borrowed-client close review made transport close idempotent across
  native owner/client races. v185 current portable Go race suite PASSED17/17
  (2.237s), including20 concurrent owner/borrower-close iterations.
  v186 current actual-source overlay suite PASSED3/3 (0.117s); Python syntax
  compilation and git diff --check passed. Native adapter tests/recipe exports
  are present; current borrowed-close implementation still needs parent-graph
  recompile after v184. No Kotlin publication changes have been enabled.
  v184 host adapter and actual SOCKS cancellation race tests PASSED.
  v187 then PASSED current borrowed-close Android arm64 compile3.125s and
  host adapter/forwarding/SOCKS race checks12.266s, including real UDP/TCP A
  wire responses through the supplied native-proxy fixture.
  Admission review closed a generation-replacement window before native
  device creation: ownership is now pinned INSIDE the engine proxy callback,
  not a later success callback. Partial starts cannot cancel/replace owners
  before confirmed stop. v188 current source PASSED Android CGO compile3.093s,
  three host adapter race tests and SOCKS TCP/UDP cancellation subtests
  (10.010s host command). Dependency declarations/sums unchanged after each
  command, recorded alongside exact source hashes.
  v190 latest actual-source overlay suite PASSED3/3 (0.168s), Python syntax
  and git diff --check passed. v189 now builds an explicitly arm64-only
  JNI/API-probe AAR from cached tools/NDK/modules, network none. It must check
  generated PrepareNativeDNS/CancelNativeDNS Java methods and exactly one
  existing libgojni.so, without pretending it is a production multi-ABI/geo
  resource package. Android runtime, Kotlin split/publication and OpenVPN3
  integrations remain unfinished; no emulator started, no final CI/push/merge.
  v189 JNI bind FAILED: gobind signal-killed; Docker measured OOMKilled=true
  at512MiB/no swap. Cached gomobile/gobind builds themselves passed
  (62.495s/5.043s); their artifacts/evidence are preserved for reuse.
  v191 WinRM measured zero services/workers/owned journals/aliases and restored
  DNS10.0.2.3 before requesting guest ACPI powerdown. No force-stop or cleanup
  kill is authorized. Full2CPU/4GiB may be reassigned to v192 ONLY after the
  wrapper has exited normally. v192 will reuse hash-checked built tools,
  retain network-none/frozen dependencies and preserve the failed v189 run.
  ACPI powerdown was acknowledged but did not stop Windows. v193 rechecked
  zero native ownership/restored DNS and requested Windows shutdown /s /t0
  WITHOUT /f. Original wrapper waiter then measured normal exit0; no terminate,
  force-stop or pending-cleanup kill was used.
  v192 PASSED arm64-only JNI/API probe with full2CPU/4GiB/no swap/network-none:
  bind80.910s, javap0.156s; generated prepareNativeDNS(String)/cancelNativeDNS()
  and exactly jni/arm64-v8a/libgojni.so. AAR SHA256
  31a5c9ad2046a5824b1e6c01e1b5500490dbe2c796f21dabbd5c1adbcaeadf89.
  This is NOT a production multi-ABI/resource package or runtime acceptance.
  Kotlin NativeDnsPlan now snapshots ORIGINAL final native route scope before
  alias capture, retains duplicate resolver occurrences, handles longest-prefix
  include/exclude, represents IPv6-only as unavailable under OFF, and refuses
  hostname/bootstrap, mapped IPv6 ambiguity, alias collisions and conflicting
  routes. It does not open sockets/select an underlay or enable publication.
  DIRECT scope still requires a pinned original-network binding adapter;
  it MUST NOT be silently forwarded through the existing tunnel proxy.
  v194 runs actual protocolApi/utils Kotlin/JUnit checks offline in2CPU/4GiB,
  including six new scope-planner tests. Result pending.
  v194 actual offline Kotlin/JUnit PASSED63/63: six NativeDnsPlan tests and
  57 existing protocolApi/utils tests, zero failures/errors/skips; build47s.
  Existing AGP8.6.1/compileSdk36 and Kotlin copy/deprecation warnings retained,
  not suppressed or treated as platform compatibility acceptance.
  Native runtime now adds explicit DIRECT scopes with a generation-pinned
  NativeDNSController socket-binding callback, required before connect.
  Missing/rejected controller, unknown scope/security, conflicting per-resolver
  scopes and lost original binding fail closed; there is no tunnel/default
  network fallback. IPv6 transport remains blocked before socket admission.
  v195 compiles current Android CGO and executes host race/no-fallback scope
  tests offline at2CPU/4GiB/no swap. Kotlin controller/lifecycle publication
  and device binding acceptance remain to integrate; current JNI probe v192
  predates the new DIRECT-controller export and is not proof for that API.
  v195 PASSED current Android CGO compile3.061s and host race command22.093s:
  five native adapter tests, including rejected original-network binding
  producing UDP/TCP SERVFAIL with ZERO tunnel fallback, plus actual SOCKS
  TCP/UDP-handshake cancellation. These are not Android Network.bindSocket
  device measurements.
  v196 current DIRECT-controller JNI/API probe PASSED: bind17.130s,
  generated registerNativeDNSController plus NativeDNSController.bindDNS(long,
  String), exactly one existing libgojni.so. Arm64 probe AAR SHA256
  093a27832444ac49edf0cd1cbc65142197ca292ffd70aae368a185426d7ea184.
  ProtocolConfig now has opt-in managed DNS publication/capture: IPv4-only
  ordered aliases are added AFTER destination split processing, without
  replacing other native routes or changing legacy ON DNS behavior.
  v197 executes Kotlin tests for include-only alias capture, preserved DIRECT
  resolver scope and publication order/admission, plus existing regressions.
  Caller wiring must still account for the actual OS route footprint
  (including Samsung's existing forced DNS host routes) before choosing scope;
  it must pin the original Network identity and honor native cleanup failure.
  Xray lifecycle/publication and OpenVPN3 interception are not yet enabled.
  v197 actual offline Kotlin/JUnit PASSED65/65 (49s): eight native DNS
  plan/capture tests and57 existing tests, zero failures/errors/skips.
  Include-only DNS alias capture preserves the original DIRECT upstream
  decision and all other native IPv4 routes; ordered alias publication and
  rejection of duplicate/non-IPv4 managed endpoints are executable checks.
  Next: wire Xray Kotlin preparation/controller/publication and confirmed
  cleanup using the verified v196 JNI API, including original-network
  identity and OS encrypted-DNS compatibility; then OpenVPN3 sole-reader
  ingress/egress. No native Android runtime/device acceptance is implied by
  these compile/host/JUnit tests. PR remains unready/unpublished, no merge.
  Android Xray Kotlin continuation now wires original-route planning (including
  Samsung DNS host routes), numeric-only prevalidation, strict encrypted-DNS
  refusal before snapshot/bootstrap, generation-pinned DIRECT controller,
  prepared managed DNS listeners before Builder.establish and IPv4 alias-only
  publication. Missing/ambiguous/changed original network, lockdown DIRECT and
  encrypted DIRECT metadata fail closed, never selecting another resolver/path.
  XrayNativeLifecycle now reserves ownership before preparation/admission,
  confirms tunnel join BEFORE engine stop and DNS release, retries only
  unconfirmed boundaries and retains ownership across native errors/exceptions.
  No CONNECTED on replacement and no DISCONNECTED before confirmed cleanup.
  Protocol/service now preserve pending ownership through exception handling,
  replacement admission, disconnect retries, service timeout and process-kill
  guards. This service integration requires its own compile/runtime evidence.
  v198 actual current Xray Kotlin compilation against hash-checked v196 JNI
  API fixture and offline JUnit PASSED78/78 (13 new Xray lifecycle/publication
  cases plus65 existing), zero failures/errors/skips. This is not service/app
  compilation, JNI invocation or Android VPN/runtime acceptance.
  v199 located cached full arm64 Android deployment. v200 now compiles the
  actual current service/app Gradle graph in an isolated copy against the
  explicitly named JNI/API-probe AAR; no native payload rebuild, downloads,
   emulator or APK/resource-completeness claim. v200 PASSED current service/app
   :compileOssDebugKotlin in90s; this predates the frontend-failure callback.
   Frontend-failure continuation: v204 Android compilation passed but host
   binaries could not execute on noexec tmpfs (harness failure retained).
   With executable RAM tmpfs, v205 PASSED nine native adapter race tests and
   SOCKS TCP/UDP handshake cancellation. Failure callback joins before owner
   retirement; intentional close suppresses notification; dead preparation and
   stale nil retirement cannot admit/drop another generation. Actual generated
   JNI exposes bindDNS(long,String) and dnsFailed(); arm64 API-only AAR SHA256
   366be6999f06ae5957bbbf7b80db7ba0ec1dac72959488c189269500084ce3fd.
   v206 current Kotlin consumer compilation/JUnit PASSED81/81, with42 of47
   Gradle tasks up-to-date; measured source delta31026bytes and workspace
   2419051→2530782bytes. No Android JNI invocation is implied.
   Test-only tagged x86_64 fault fixture (not exported by production recipe):
   v207 native race checks passed but JNI linker failed with Bus error.
   Instrumented same-input v208 link PASSED; measured memory peak1425846272
   bytes, minimum free tmpfs444805120 of536870912bytes, zero OOM events.
   The original linker failure remains unexplained, not declared resolved.
   v209 probe APK compilation failed on non-exported JNI compile dependency;
   explicit test-module-only dependency fixed it. v210 test-only APK assembled
   in23s (8 executed/86 up-to-date), SHA256
   a72e5be0ee85d96882d3acb6d708f246019027115f654ee03375a1ad47c78a4c.
   This is NOT device/runtime acceptance; emulator remains stopped.
   v211–v213 full-service harness failures are retained: init-script leakage
   into included plugin build, read-only Android analytics home, and too-late
   artifact mutation. The corrected v214 selects an owned JNI build override
   before project configuration and PASSED current service/app
   :compileOssDebugKotlin in34s (4 executed/62 up-to-date), offline within
   2CPU/4GiB/no extra swap. Existing v200 deployment tree is reused; historical
   logs/manifests and original JNI recipe remain unchanged, mutable sources are
   tracked separately by the cache ownership manifest.
   Full device lifecycle, Network.bindSocket/UDP/TCP/split acceptance and
   OpenVPN3 remain unfinished.
   OpenVPN3 preparation now separates the DNS-only gVisor packet endpoint from
   AWG's application-flow/path-recovery machinery. It uses the same pinned
   packet dependency, owns only its capture address and has no dialer, OS TUN
   or independent native reader. v215 PASSED all16 dnsguard cases in ten
   race-instrumented repetitions, including existing IPv4/IPv6 UDP/TCP NODATA,
   forwarding/cancellation, native byte/headroom preservation and three new
   packet-owner validation/join/isolation tests. This remains a portable
   primitive measurement, not an OpenVPN3 adapter/runtime acceptance result.
   v216 shared PacketSession PASSED20 dnsguard race cases, including callback-
   joined release, intentional-close suppression and scoped UDP/TCP forwarding.
   OpenVPN3 continuation extends the EXISTING Cloak shared Go runtime, not a new
   production runtime/library. Its original dependency source closure is import-
   namespaced, retaining every old version/source hash/license while DNS uses
   the already locked routing graph. v217 actual host c-shared build and source/
   binary TCP-provenance verification PASSED; bootstrap wrote12632199 source
   bytes once in the stable workspace. Subsequent v218/v221/v222 reuse wrote0
   source bytes; no SDK/toolchain/full OpenVPN tree was copied.
   v218–v220 native owner fixtures passed real libck C ABI checks with C++
   ASan/UBSan. v220 additionally PASSED four actual Cloak policy race tests:
   default/missing ON, generation ownership, hostname/IPv6 refusal before
   resolver/socket admission and policy retention during an in-flight dial.
   Its SWIG stage FAILED because the relocated tool lacked SWIG_LIB; failure
   retained, corrected to the existing installed bin/swiglib, no download.
   v221/v222 PASSED native UDP AND raw TCP DNS through the real C ABI, including
   split two-byte length prefix, two queries on one TCP stream, preserved A/AD,
   local unauthenticated AAAA NODATA, no IPv6 exception, distinct capture aliases,
   stale handles, retained output-descriptor ownership and concurrent stop.
   v222 measures per-frontend retired callbacks while the full policy owner
   remains retained until explicit confirmed retirement. The detached native
   resolver lease barrier is exercised as a native-owner fixture; actual
   resolver/VPN lifecycle acceptance is not yet claimed.
   Both original ovpncli.cpp and current generated SWIG director compile with
   the actual Android NDK27/API24 compiler and checked include overlay. Platform
   detection is tested without a manual Android platform define. Existing
   upstream Cloak ambiguous-base warning remains visible, not suppressed.
   Current compile-only SWIG fixture JAR SHA256
   92d79a3d958d36f7e4bf734170ed1e7123eb4be0d98984433bf0e6223bf9e192.
   This is not linked Android libovpn3/JNI invocation or VPN runtime evidence.
   Shared Kotlin NativeDnsPublication and explicit AF_INET DNS socket helper
   are now being compiled in v223. Production OpenVPN3 recipe/export wiring,
   Kotlin connection lifecycle/relay and device acceptance remain unfinished.
- 2026-11-25 production Linux OpenVPN packaging continuation:
  The production recipe now preserves the native ELF's private library bytes
  with a checksummed source manifest. Build/install deployment uses that closure,
  not the service's same-SONAME OpenSSL, and changes only executable RPATH.
  `openvpn-production-packaging-20261125-v3/report.json` records actual recipe
  and CMake execution: exact closure, relocated producer RPATH, corrupt-library
  rejection, unchanged service crypto, immutable source and self-copy refusal.
  `openvpn-production-installed-audit-20261125-v1.json` records all four native
  dependency hashes unchanged after standard cmake install; native and service
  libcrypto resolve independently. No post-install library repair was used.
  `systemd-installed-startup-20261125-v17-actual-ifw.json` records installation
  of the actual offline CPack IFW .run into disposable PID-1 systemd, installed
  manifest/ldd audit, active Xray teardown and authenticated TLS OpenVPN restart.
  `systemd-installed-startup-20261125-v18-ifw-purge.json` additionally records
  actual maintenance purge, removed executables and LoadState=not-found.
  `systemd-installed-startup-20261125-v21-ifw-blocked-purge.json` executes
  maintenance purge while the service is already deactivating behind a foreign
  DNS edit: the same service PID, live NODATA listeners, unit and payload files
  remain until confirmed restore, then DNS/aliases retire and purge completes.
  Both hooks now wait for stop even in deactivating state and refuse to proceed
  on failed stop or unconfirmed inactivity. Observer failures v19 (removed Qt)
  and v20 (noexec fixture storage) are retained separately; v21's final observer
  uses its measured dependency copies outside the installed payload.
  Installer hooks now support already-root execution without sudo and require
  daemon reload, successful service start/enable and active/enabled checks.
  IFW discovery failure v1 and missing guest OS library failure v16 remain
  preserved; the latter was addressed with measured cached OS libraries only.
  Final hosted CI, reboot and remaining platform/backend acceptance remain
  outstanding. No push or merge occurred.
- 2026-11-25 active systemd children continuation:
  `systemd-installed-startup-20261125-v14.json` records real PID-1 systemd,
  active Xray/tun2socks stop and real TLS OpenVPN restart. Failed DNS restore
  retains the same native child PID, TUN, routes and live AAAA NODATA listeners;
  fixing the external DNS edit permits joined worker/process exit, engine/
  TUN/capture retirement, baseline routes/rules and a fresh service PID.
  OpenVPN uses the production IPv6 blocking directives and authenticated TLS/
  EKU checks; its replica records 0/NormalExit and native restore ACK precedes
  TUN closure. The raw DNS crash-recovery and pending-stop cases also execute.
  v10 separately completed the active Xray case.
  The test exposed a production orphaned persistent tun2 after service quit:
  shutdown now freezes native starts, joins process descriptors, stops the
  service Xray engine and deletes only its owned proxy TUN before quitting.
  It no longer relies on QProcess destruction or process exit for that cleanup.
  Worker fixtures now wait for actual STACK readiness before DNS publication.
  v8's earlier pre-readiness ownership wait and v9's captured orphaned TUN
  failure remain preserved, not counted as passes.
  Native v11 was deployed with an explicitly recorded RPATH-only change and
  its exact frozen OpenSSL files in a private dependency directory:
  `systemd-install-stage-20261125-v5/openvpn-deployment.json`.
  An earlier standard-prefix staging check found a different service
  libcrypto being selected; that failed closure report is retained as
  `openvpn-systemd-deployment-check-20261125-v1.json`. This fixture isolation is
  NOT a completed production installer dependency/provenance audit.
  v11-v13 fixture failures (systemd HOME/config path, Type=simple IPC-readiness
  timing and root-owned state-file enrichment) remain distinct. Readiness now
  uses a non-mutating QtRO probe, and journals are checked in both actual
  possible systemd config roots before teardown. Diagnostic state is captured
  before terminating the replica; v12's pre-TLS diagnostic native-log field is
  historical content and is not a native acceptance result.
  `systemd-active-shutdown-build-20261125-v1.log` records current production
  service link/install. `systemd-active-children-regression-20261125-v1.log`:
  session 10 passed, transaction 14 passed, service 15 passed / one child-only
  skip, nine production TUs compiled plus native overlay/helper regressions.
  All execution remains offline, aggregate 2 CPU / 4 GiB / zero swap.
  Reboot, other backend/platform integrations, packaging audit and final
  hosted CI/PR publication are still outstanding; no push/merge occurred.
- 2026-11-25 real systemd continuation:
  `systemd-installed-startup-20261125-v7.json` passes with systemd as actual PID 1
  (manager running), current installed service and shipped unit. Startup and
  restart produce active/running processes; SIGKILL triggers Restart=always
  and durable DNS snapshot recovery, alias retirement and working new IPC.
  A second guarded publication plus external DNS edit leaves systemctl stop
  deactivating with the same main PID and live AAAA NODATA listeners. After
  resolving the edit, stop confirms restored OS DNS, retired aliases/journals,
  inactive state and Result=success. This uses a real native link/DNS owner;
  active OpenVPN/Xray/WG child teardown under systemd and reboot acceptance
  are separate remaining cases.
  The experiment found a production failure in v5: SIGTERM previously exited
  without restoring published DNS. Existing Unix SignalHandler now routes
  shutdown through LocalServer: stop accepting IPC/publications, retain owner/
  listeners while restore is uncertain, then quit only after confirmation.
  Linux unit uses KillMode=mixed and TimeoutStopSec=infinity so systemd does not
  kill native children before the service completes that barrier. A foreign DNS
  edit can deliberately hold stop pending; administrator SIGKILL remains a
  forced-crash boundary and is tested via durable startup recovery.
  Cached systemd image was booted in private PID/cgroup/network namespaces
  with a writable private cgroup mount (no host cgroup bind), parent limits
  measured 2 CPU / 4 GiB / swap 0. SYS_ADMIN/NET_ADMIN and container-local
  AppArmor/seccomp relaxation permit nested systemd, without --privileged.
  Minimal guest OS libraries missing glib were supplied from the measured
  existing Ubuntu build-image closure, not downloaded; manifest:
  `systemd-guest-os-libs-20261125-v1/manifest.json`. Private resolved/bus are
  real systemd fixture units; the application unit drop-in changes only their
  dependency/environment, not shutdown/restart semantics. All earlier boot,
  fixture and failing shutdown reports remain preserved (v1-v5).
  `systemd-shutdown-service-link-20261125-v1.log` records current service link/
  install. `systemd-shutdown-regression-20261125-v1.log`: session 10 passed,
  transaction 14 passed, service 15 passed / one child-only skip, nine production
  TUs compiled and native overlay/helper regressions passed. No hosted CI,
  push or merge. Cross-platform lifecycle/backend completion remains required.
- 2026-11-25 shipped GUI + installed-layout continuation:
  `xray-shipped-gui-20261125-v6.log`: 3 passed, 0 failed, 0 skipped. Current
  client/service are installed by real `cmake --install` into disposable
  `/opt/AmneziaVPN`; service runs at the shipped unit's exact ExecStart path.
  The test instantiates the real AmneziaApplication, loads the shipped QML
  entrypoint with real repositories/controllers and imports through the normal
  --import path. Mouse input targets the shipped PageHome ConnectButton for
  both connect and disconnect. Refused DNS restore retains TUN/journal owner/
  engine token across automatic retries; resolving the edit confirms TUN and
  journal deletion, engine token retirement and the final GUI state.
  `xray-shipped-gui-20261125-v6/installed-provenance.json` records installed
  client/service/worker hashes, resolved dependencies and the shipped unit.
  Static tun2socks is identified by measured ELF program headers, not treated
  as an unresolved dynamic dependency.
  The executable is the normal project test target with actual application
  objects and shipped resources, using a test main for offscreen mouse
  automation, not the production executable's main. This is installed-layout
  runtime, NOT systemd unit restart/reboot/privilege-boundary acceptance.
  Normal target compile/link is in
  `xray-shipped-gui-normal-target-20261125-v3.log`.
  Failures remain separate: v2 was a static-ELF dependency-checker assumption;
  v3 exposed missing transitive OBJECT-library QML registration in the test
  target; v4 and v5-debug diagnosed a dangling QJsonValueRef in the fixture's
  journal-owner assertion. The fixture now stores a QJsonValue, with the same
  owner-retention assertion; no production check was weakened.
  Required final Linux CI also runs the shipped GUI test in a private installed
  prefix; no hosted dispatch/push/merge occurred.
- 2026-11-25 full-client/actual-class GUI continuation:
  `desktop-client-full-link-20261125-v1.log` records 232/232 and full
  AmneziaVPN executable linking offline. `desktop-client-full-smoke-20261125-v1.json`
  records actual --version exit 0, resolved loaded libraries and binary SHA256.
  Existing temporary-file/named-enum compile warnings and CLI thread-storage
  diagnostics remain in the logs; none was silenced.
  `xray-full-client-gui-20261125-v3.log` runs actual production XrayProtocol,
  VpnConnection and IpcClient objects from that client, not an extracted stop
  body. Offscreen QML mouse input initiates disconnect against the real service/
  Xray/tun2socks/private resolved. Four failed automatic retries preserve
  protocol identity, journal owner, worker PID, engine token, TUN index and IPv6
  capture. After the fixture resolves the external DNS edit, only the production
  timer retries: Disconnected, VpnConnection release, worker/engine stop, TUN/
  journal deletion and baseline IPv6 routes/rules are confirmed.
  `xray-gui-normal-test-target-20261125-v1.log` additionally compiles/links the
  normal project test target (181/181). Its real execution is
  `xray-full-client-gui-20261125-v4.log`: 3 passed, 0 failed, 0 skipped.
  The earlier v1 GUI test failed because mouse input preceded initial scene
  exposure; it is preserved. The corrected fixture asserts scene readiness,
  actual QML action delivery and Disconnecting before testing retries.
  This is a minimal QML control plus real client classes, not the shipped
  application's complete page/controller/repository flow or installed service.
  Repository-not-initialized diagnostics from the deliberately minimal
  VpnConnection fixture remain visible. Required final Linux CI now invokes
  the normal test target in a bounded private service/resolved namespace;
  hosted execution is deferred until implementation is complete.
- 2026-11-25 real Xray/QtRO stop continuation:
  `xray-real-stop-20261125-v4.log` passes with the actual linked service,
  DNS-enabled Xray archive, real Xray SOCKS negotiation, real tun2socks process,
  service-created TUN, native Linux IPv6 capture and private resolved.
  The fixture executes the verbatim production stop body in a minimal QtRO
  caller context (not the full XrayProtocol object or GUI).
  An external DNS edit refuses restore: owner/TUN/worker/engine/native capture
  remain; the external DNS selection is not overwritten. Real UDP/TCP AAAA
  NODATA and IPv6-only A SERVFAIL still pass against retained aliases. After
  resolving the edit, retry confirms worker join, TUN deletion, Xray stop,
  journal retirement and baseline IPv6 routes/rules. This measures native
  capture protection, not a separately enabled KillSwitch policy.
  Cgroup measured 2 CPU / 4 GiB / zero swap, network disabled.
  v1 failure found root-service createTun unnecessarily depended on sudo;
  root now executes the same iproute2 commands directly, while the non-root
  path retains sudo. Service relink:
  `desktop-service-root-tun-link-20261125-v1.log`.
  v2 was a fixture platform mismatch (Windows/macOS-only setNativeIpv6Blocked);
  Linux fixture now follows production configureProxyIpv6. Both failure logs
  are preserved. v3 passed before adding real DNS queries/baseline-rule checks.
  Remaining scope includes full GUI/caller lifetime, installed-service,
  separately enabled KillSwitch, other platforms and final hosted acceptance.
- 2026-11-25 desktop Xray stop continuation:
  failed/unconfirmed DNS restore or absent IPC no longer clears the DNS owner,
  disables protection, deletes the TUN or stops native resources. Cleanup uses
  retryable confirmed phases: DNS restore, worker join, TUN deletion, owned
  engine stop, protection disable, then owner release/Disconnected. Late setup
  callbacks are generation-invalidated. Destruction retains the owner and
  retries instead of authorizing teardown on a timeout; unavailable IPC can
  therefore hold destruction pending. Full GUI/service-loss recovery remains
  required before merge.
  `xray-production-stop-failure-retry-20261125-v1.log` executes the actual
  production stop body with injected refused/lost restore replies and missing
  IPC: all resource/owner retention, retry ordering and Disconnected assertions
  pass in isolated Linux and Windows preprocessor branches. This is NOT native
  Windows or real Xray/QtRO backend acceptance.
  `xray-stop-restore-retry-20261125-v2.log`: sequence runtime tests cover all five
  failure/retry boundaries, exact ordering, no repeated confirmed phases and
  reentrancy; current XrayProtocol and IpcServerProcess compile with regenerated
  RPC headers. `processStopped()` confirms an already stopped/joined worker
  without relying on QProcess::waitForFinished on NotRunning.
  `desktop-service-xray-stop-rpc-link-20261125-v1.log` records successful current
  service relinking with that RPC. Required final Linux CI includes both new
  lifecycle tests; no hosted CI was dispatched.
- 2026-11-25 reconnect continuation:
  `openvpn-tls-reconnect-20261125-v2.log` passes actual native SIGUSR1/
  persist-tun TLS reconnect after SIGKILL of the QtRO replica. Same service,
  native PID, DNS owner, native interface index and aliases survive; actual
  UDP/TCP NODATA/SERVFAIL still pass. Reattached stop confirms restore ACK
  before TUN teardown and aliases/journal retirement.
  The first attempt (`...-v1.log`) correctly refused a preserved frame missing
  `dev`: c2.es is recreated on restart. Native export now takes the actual
  retained c1.tuntap name, never configured --dev or stale service metadata.
  `openvpn-native-preserved-interface-20261125-v11.log` records the new helper
  regression, checked overlay tests and full offline native rebuild with the
  unchanged cached dependency closure. Native v11 SHA256:
  `bcf2fec4c9799e8b2468e772566746abc56850961da633ecb04db7ddb3237b00`.
  Service bytes remain the v9 measured service below. Cgroup: 2 CPU / 4 GiB /
  zero swap; network disabled. This does not measure retained TCP, full GUI,
  installed-service startup or other-platform runtime.
- Full current Linux service linking and real TLS/QtRO process-loss checkpoint:
  `desktop-service-link-20261124-v7.log` records the final service relink;
  `openvpn-tls-qtro-20261124-v9.log` passes with service SHA256
  `265dd9913d5feeb7450a3787085a3a279c7bf64cfb36916f834a06ef28a48654`
  and native OpenVPN SHA256
  `a793cbc7fa6ce722fef30f3047e632a418eb8004455574b8381eccb6ed03dfb2`.
  Native v10 was rebuilt offline because its management restore-query changed;
  its manifest confirms the existing dependency closure is unchanged.
  Actual CA/server EKU checks and TLS 1.3 precede CONNECTED; server-pushed
  search/resolve domains reach the production service and private resolved.
  Real UDP/TCP NODATA/SERVFAIL pass both before and after SIGKILL of the QtRO
  replica process. A new replica attaches and stops the same native owner;
  native restore ACK precedes TUN teardown and finished is 0/NormalExit with
  aliases/journal retired. This uses a small QtRO client, not the full GUI,
  and a console service, not systemd/SCM/launchd installation acceptance.
- Causal fixes from this measurement: native DNS recovery/factory initialization
  moved to LocalServer before IPC opens (Linux/console previously bypassed
  SystemService::start); native restore queries can wait for ACK despite a
  pending shutdown signal, without clearing or replacing that signal; QtRO
  process sources register once after the first transport connects; native
  management disconnect gets a bounded restore-gated grace rather than killing
  an otherwise normally exiting process. Ordinary credential queries are
  unchanged. Failed TLS fixture logs v1-v8 remain separate: compile include-path
  failure, DNS factory failure/diagnostics, native shutdown-signal failure,
  premature QtRO registration, and normal-disconnect/kill race are not passes.
- `openvpn-post-tls-regression-20261124-v1.log`: session 10 passed,
  transaction 14 passed, actual service 15 passed / one child-only skip;
  eight production TUs compiled, native checked/idempotent overlays/helper
  tests passed. Measured 2 CPU / 4 GiB / zero swap, network disabled.
  Full GUI/application linking, installed-service acceptance, restart/error/
  retained-TCP/split cases, remaining platform/metadata/backend integrations
  and final hosted CI/publication remain outstanding.
- Linux scoped publication is now wired from Router's OpenVPN selection through
  DnsUtils to the durable resolved snapshot. One modern plaintext resolver group
  supports ordered search domains and resolve domains; legacy DOMAIN and
  DOMAIN-SEARCH retain global selection. Other platform adapters still reject
  scoped input. Multiple groups, DNSSEC/SNI/encrypted transport and unrecognized
  legacy domain contracts remain explicitly refused.
  `openvpn-scoped-publication-20261124-v3.log`: actual DNS-enabled guard,
  aliases and private resolved publication/restore passed, including distinct
  endpoints for duplicate IPv6-only upstreams, UDP/TCP AAAA NODATA and A
  SERVFAIL, scoped-to-global replacement, newly affected peer root-domain
  snapshot/restore, and alias/journal retirement. Security downgrade refusals
  are asserted. Session 10 passed; transaction 14 passed; service 15 passed
  with one child-only skip; eight production TUs compiled. Limits measured:
  2 CPU / 4 GiB / zero swap, no network or native rebuild.
  This remains direct production-adapter testing, not native TLS/QtRO or
  installed-service acceptance. Next: remaining metadata/platform adapters
  and full current service linking/native TLS hand-off.
- Scoped adapter groundwork: Linux recovery capture now accepts an explicit
  ordered search/routing-domain list and default-route value. Scoped snapshots
  do not displace another interface's root domain. The selector still refuses
  scoped inputs until publication wiring is implemented; this is not scoped
  OpenVPN backend acceptance.
  `openvpn-scoped-recovery-20261124-v1.log`: actual private resolved writes,
  reads and confirmed restoration of mixed search/routing domains passed.
  Session 10 passed, transaction 14 passed, real-service 14 passed / one
  child-only skip; eight production TUs compiled. Measured 2 CPU / 4 GiB /
  zero swap, network disabled, unchanged native binary not rebuilt.
- Added OpenVpnDnsSession in the existing service and configure/command/stopped
  process IPC. Desktop explicit OFF now uses the service's management socket;
  the GUI only receives ordinary management lines. Publication checks complete
  native route evidence and fresh request serials; preserved routes need the
  active owner/interface. Native metadata is included in the durable DNS journal.
- The bundled resolver script is omitted only for classic desktop OFF; exact
  omission tests retain unrelated/malformed caller input. The native opt-in
  refuses caller scripts rather than executing a competing writer.
  `openvpn-inline-credentials-session-20261124-v5.log` additionally executes
  literal/single-/double-quoted inline credential-block cases: their contents
  are byte-for-byte retained. Session suite: 10 passed; production configurator
  compilation passed. `openvpn-production-owner-gate-20261124-v5.log` records the
  final process-owner admission-gate compile.
- close/terminate/kill requests use the checked DNS stop path. Source routing/
  DCO cleanup and finished notification wait for DNS cleanup. Graceful-stop
  fallback killing is armed only after restoration; a reentrant stop during
  publication cannot send success. Legacy ON native processes also reserve the
  service's native-process owner so they cannot race a managed DNS publisher.
- `openvpn-service-real-dns-20261124-v6.log`: session/selection/script suite
  10 passed; generic transaction suite 14 passed; real service suite 13 passed,
  0 failed and one child-only skipped slot (executed by the crash tests).
  Includes actual UDP/TCP NODATA, IPv6-only A SERVFAIL on duplicate endpoints,
  real resolved publication, preserved replacement, journaled native metadata,
  GUI-observer loss, external DNS edit refusal and confirmed restore/alias removal.
  The native management peer is modeled; this is NOT native TLS/QtRO GUI-loss
  or installed-service acceptance. Imported production-runtime consumer CMake
  was exercised, not a stub DNS library.
- Refused policy/failed prepare/unsupported metadata no longer triggers a
  platform DNS reset when no publication was attempted. The same executed
  regression checks protect a legacy ON publication from a foreign owner.
- The same log records current production compilation of eight service/client/
  router/protocol/configurator TUs against regenerated RPC headers and native
  function/helper tests. Cgroup measurement: 200000/100000 CPU, 4294967296 bytes
  memory, zero swap. No network, package fetch, VM or Android emulator.
- Current native source was fully rebuilt in v7. Its first competing-script
  assertion used non-executable /dev/null and measured an earlier X_OK refusal.
  The binary and failed manifest are preserved unchanged. With executable
  /bin/true, `openvpn-native-service-activation-20261124-v9.{log,json}` measures
  the intended ownership refusal on that same v7 binary and confirms all four
  loaded-library paths/hashes unchanged. v8 was a driver quoting failure, not
  a native acceptance attempt; all failure logs remain separate.
- Important incomplete scope: scoped/search-domain/DNSSEC/multiple-priority
  native DNS policies are currently refused, not flattened. Their OS metadata
  adapter remains required for merge. Current service/full-client linking,
  actual TLS/OpenVPN + QtRO GUI disappearance, Windows/macOS runtime,
  IKEv2/Android and final full builds/CI/PR publication are still outstanding.
  Required final Linux CI now includes the session suite and isolated real
  resolved transaction suite using the service's actual linked runtime.
  No intermediate push/CI dispatch or merge was performed.
- Resumption point: finish policy-aware DNS metadata publication, then link/run
  the current classic service and exercise real TLS OpenVPN plus QtRO GUI loss
  (not the observer model). Continue remaining IKEv2/Android integrations before
  final hosted platform/installed-service acceptance and PR publication.

Earlier local checkpoint (2026-11-23, superseded in part by the continuation below):
- Windows external-DNS overlay now covers both the shipped root DLL and tunnel
  address configuration paths. Checked-overlay tests pass on pinned source.
  Production Go packages cross-compile with unchanged upstream go.mod.
  Upstream winipcfg test vet errors (`Errorf` with `%w`) are retained separately
  in `native-wg-dns-local-integration-20261123.log`; no test assertion was weakened.
- Managed Windows DNS has an independent dynamic WFP lease restricted to local
  IPv4 alias UDP/TCP port 53. Windows runtime behavior remains unverified.
- Resolver transactions reject stale owners. IPC carries user IPv6 policy,
  owner identity, and DNS failure notification. Desktop Xray now requests OFF
  publication after native routing and uses generation-checked callbacks.
- Linux transaction/service tests with real isolated aliases pass:
  `native-dns-owner-transaction-20261123.log`. Xray production translation unit
  compiles against freshly generated IPC replica headers:
  `native-dns-xray-ipc-compile-20261123-v2.log`. This is not full app/service
  linking or backend runtime acceptance.
- Automatic crash recovery, remaining native OpenVPN/IKEv2/Android integration,
  full platform builds and final hosted acceptance are still outstanding.
  No intermediate CI dispatch or push has been performed.

2026-11-24 continuation (still uncommitted, no intermediate CI):
- Production Linux `ipcserver.cpp`, `router.cpp`, and `router_linux.cpp` compile
  against freshly generated IPC source headers:
  `native-dns-service-ipc-compile-20261124.log`.
- Failed guard preparation now retains cleanup ownership if alias retirement
  fails. Regression coverage checks that stale owners cannot clean it up and
  that cleanup is retried before another generation is admitted.
- Service health now checks the captured resolver interfaces, not just the
  native listener interface. An isolated real-alias test takes the resolver
  loopback interface down while the VPN fixture stays up and verifies failure.
- `native-dns-scope-health-20261124.log`: NativeDnsTransaction and NativeDnsService
  both pass (2/2 CTest targets, 0 failed). Checks stay within 2 CPU / 4 GiB,
  no swap, offline namespace; no host interface changes or Android emulator.
  This does not resolve the remaining integration/runtime acceptance items above.

Owned-alias crash recovery layer (2026-11-24, not production activation):
- New journals use schema 2, canonical serialization and a payload checksum;
  each live guard holds a process lock. Recovery rejects legacy/corrupt/unknown
  records, live owners, changed native identity, moved aliases, and addresses
  whose installation was never confirmed.
- `recoverNativeDnsServiceGuards` requires an explicit successful OS-DNS restore
  callback before removing aliases; it rechecks journal and interface identity
  after that callback. Failure preserves the record for retry.
- Real namespace test launches a child with the existing Go listener and assigned
  alias, then exits via `_Exit(77)` without destructors. It verifies refused DNS
  restore, modified record/interface, late journal edit, successful ordered cleanup
  and idempotent retry. `native-dns-crash-recovery-20261124-v2.log`:
  2/2 CTest targets pass; service suite 7 passed, 0 failed, 1 child-only slot
  skipped in the parent (the child slot executes in the crash subprocess).
- IMPORTANT: the test supplies the DNS confirmation callback. Durable platform
  OS-DNS snapshots/compare-and-restore and startup wiring were unimplemented at
  this checkpoint (Linux continuation below supersedes that limitation on Linux).
  There is deliberately no unconditional-success production callback. This
  layer alone is not complete OS-DNS crash recovery or merge readiness.

Linux durable OS-DNS recovery continuation (2026-11-24):
- OFF now captures the affected systemd-resolved link DNS, ordered domains and
  effective DefaultRoute values before publishing managed DNS. The original
  snapshot survives listener reuse/replacement. It is saved in the owned journal
  by QSaveFile; Linux also fsyncs the directory entry before any OS mutation.
- Both normal strict teardown and service startup use compare-and-restore.
  Fields must match either their original or intended managed value, allowing
  interrupted publication/restoration without adopting external edits. Every
  affected link is checked before mutation and after restoration. Native aliases
  are removed only after restoration confirms; uncertain/unknown state stays.
- SystemService runs recovery before LocalServer and disables new OFF guards if
  unresolved journals remain. Multiple retained generations share validated
  alias ownership during identity checks; startup makes another pass only when
  journal cleanup made progress.
- Real private systemd-resolved + D-Bus tests run without host sockets/network,
  using the existing host binaries/libraries mounted read-only (no downloads).
  Tests cover `_Exit(77)` before/partial/complete publication, two generations,
  an external DNS edit, interrupted restore, repeat startup, and graceful
  reuse/replacement/restore. Original DNS includes IPv4 and IPv6; a second link's
  root and scoped domains are restored too. This is real Linux OS-DNS testing,
  not a substituted confirmation callback.
- Final evidence: `native-dns-real-os-crash-recovery-20261124-v4.log`:
  2/2 CTest targets pass; transaction suite 12 passed, service suite 12 passed,
  0 failed (one child-only slot is skipped in the parent, executed by subprocess).
- Production SystemService, Linux DNS utility and recovery-adapter translation
  units compile: `native-dns-linux-startup-compile-20261124.log`.
- Windows/macOS durable snapshots and startup recovery remain outstanding.
  Full platform linking/acceptance, other native adapters and final CI remain
  required; no intermediate push/CI or merge has been performed.

Windows/macOS recovery implementation and native-fixture preparation (2026-11-24):
- Both desktop utilities now capture durable recovery state through the guard
  before managed publication and use compare-and-restore on strict teardown.
  SystemService startup dispatches to the platform adapter; unresolved state
  disables new managed DNS instead of deleting aliases on assumed success.
- macOS stores the complete DNS property-list dictionary (including absence),
  preserves non-server metadata during managed publication, and uses CFEqual
  rather than binary serialization order for comparisons. Service enumeration
  is anchored to parent keys, not DNS child dictionaries.
- Windows records per-GUID IPv4/IPv6 static-server configuration separately
  from DHCP mode and changes only nameserver flags, leaving suffix and
  registration metadata untouched. Native API/runtime semantics still require
  verification; this source implementation is not a Windows acceptance claim.
- The portable comparison suite passes: `native-dns-settings-recovery-portable-20261124-v2.log`
  (7 passed, 0 failed, 7 explicitly skipped native/child-only cases).
- Native fixtures now cover absent/automatic and static configurations at
  before/partial/complete publication boundaries, abrupt child `_Exit(77)`,
  external edits, and idempotent restore. macOS uses two owned synthetic service
  dictionaries, never publishes over real host network services. Windows creates
  and closes its own disposable Wintun adapter using the existing pinned DLL.
- Final hosted workflow steps have been added, but not dispatched for current
  changes. Local Windows reused the existing VM, under 2 CPU / 4 GiB container
  limits with host swap disabled; WinRM returned empty HTTP 500 before compilation.
  Preserve `windows-dns-recovery-native-20261124.log` and
  `windows-dns-recovery-vm-diagnostic-20261124.log`: neither is a test pass.
- Native platform compilation/runtime, actual platform alias cleanup after OS
  restore, remaining adapters, final current-source CI and publication remain
  outstanding. No merge is authorized.

Separate requested historical macOS installer:
- The requested application source remains exactly `9d1a3ae`, not this working
  tree. Run 45368204615 never acquired an ARM runner (zero build steps).
  Only the dedicated package-builder branch was updated (`fb4ad24`) to use an
  Intel host/Xcode 26.0 while retaining universal arm64+x86_64 checks.
  Run 45371592002 is the replacement installer build; its result does not verify
  the uncommitted PR changes or close current-source acceptance.

Native Windows recovery result / historical macOS package completion (2026-11-24):
- Reused the same owned Windows VM at 2 CPU / 3 GiB guest RAM inside the
  2 CPU / 4 GiB, no-host-swap container. GUI diagnostics confirmed a healthy
  boot; a local WinRM service restart restored remote execution without changing
  authentication, quotas, or test assertions. Original HTTP-500 failures remain.
- First native builds exposed future ZIP mtimes (source/guest timezone mismatch)
  and WinSock header ordering errors. Only future extracted timestamps were
  normalized; winsock2/ws2tcpip includes were corrected in production sources.
  Failed build evidence is retained, not relabeled.
- `windows-dns-recovery-native-msvc-20261124-v4.log`: native MSVC compilation of
  WindowsDnsRecovery, DnsUtilsWindows and the fixture passed; 13 tests passed,
  0 failed, one child-only slot skipped by the parent and executed by the six
  crash subprocess scenarios. Actual SetInterfaceDnsSettings/registry state on
  owned disposable Wintun adapters covered DHCP/static, before/partial/complete
  publication, external DNS edits and repeat restore. This does not yet prove
  full-service startup or actual Windows service alias retirement.
- Test DLL SHA256: `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
  Current-source transfer ZIP SHA256:
  `2c743797eb7ae118421ef2ff85b8652b90783c8c06829b3d1dc483be3a426c6f`.
  No dependency versions/downloads changed. The VM was shut down afterwards.
- Historical macOS installer run 45371592002 succeeded. Its verified manifest
  identifies application source `9d1a3ae54290cc43715a55b16d26d94b6f84914d`,
  universal app/service, ad-hoc application signing, unsigned/non-notarized
  installer and no Network Extension. Artifact 14910903290 contains
  `AmneziaVPN_5.1.0.0_macos_universal_9d1a3ae_TEST.pkg` (115647421 bytes),
  SHA256 `0a930c4b6bad7f7281901255014aaca657135455fe0cc40b981eb3b1a3bb25d1`.
  This old-source installer is NOT current PR recovery acceptance.

Production Windows guard/startup/alias lifecycle (2026-11-24):
- Earlier native OpenVPN protocol-only stage (superseded by service/caller source
  wiring at the top of this file): the opt-in suppression/restore barrier was
  added to the checked recipe overlay but was not yet enabled by the client.
  Full contract and current scope are in `OPENVPN-DNS-HANDOFF.md`.
- `openvpn-native-dns-full-build-20261124-v5.log`: actual overlaid do_route,
  run_dns_up_down, do_close_tun and metadata-export tests pass under instrumented
  OS boundaries, including failure/cleanup, persist-tun, original options,
  priorities and stale SNI/server/search removal (ASan/UBSan). Native helper
  Linux/Windows-branch tests pass, including exact ACK, serial exhaustion,
  failed query, retry/block and zeroization. A complete Linux OpenVPN 2.7.0
  binary was rebuilt and --version executed offline from existing sources.
  Loaded native dependency paths/SHA256 values match the cached baseline in
  `openvpn-native-dns-20261124-v5/manifest.json`; no packages were downloaded.
  Both down-pre modes and the early untyped DCO close path are included.
  The actual binary also rejects missing/nonlocal/non-client management options.
- Initial native link failure (full-build v1: unavailable openvpn_snprintf and
  private static DNS serializer) was fixed using snprintf and a narrow wrapper
  of the upstream serializer. The isolated helper v1 had an incorrectly
  acknowledging "forever-failing" fixture; it was corrected to keep returning
  cancel. The v3 extraction build hit upstream's unused Windows duri parameter;
  that harness now matches the existing production -Wno-unused-parameter flag.
  Failure logs remain separate; behavioural assertions/timeouts were not relaxed.
  Full-build v2/v3/v4 are historical intermediate candidates, not current v5.
  The first CLI-smoke harness incorrectly expected --help exit 0; the diagnostic
  and cached baseline both measured upstream exit 1. The corrected test compares
  against that measured baseline and still requires all invalid modes to fail
  at the specific external-DNS validation boundary (logs preserved separately).
- These measurements do not establish a native TLS tunnel, installed service,
  macOS/Windows runtime, or service-guard publication/restore end-to-end.
  The service-owned ACK handler, platform metadata publication and atomic caller
  activation (including omitting the competing bundled script) remain unfinished.
- OpenVPN integration prerequisite: IPv6-OFF now requests native management
  UPDOWN environment frames and retains the completed UP environment verbatim,
  including negotiated DNS metadata. Reconnect/start invalidate old frames;
  malformed/duplicate/oversized frames invalidate the snapshot and report an
  error. Full environment values are not logged. ON launch arguments are unchanged.
  Cached 2.7.0 `init.c:do_route` sends UP even if add_routes fails: this event
  must NOT alone authorize DNS publication. Cached `dns.c:run_dns_up_down`
  also applies DNS before this event, so disabling/replacing native DNS
  publication and coordinating service-owned pre-teardown restore remain
  necessary; this collection is not the completed OpenVPN guard integration.
  Standalone `tests/openvpn-management-environment` Release CMake/CTest:
  1/1 passed in offline 2-CPU/4-GiB container; separate ASan/UBSan parser run
  passed. Host CMake was unavailable; cached container CMake was used.
- Follow-up found/fixed two real transport gaps: IPC argument sanitization
  discarded `--management-up-down`, and ManagementServer consumed incomplete
  TCP lines. The real sanitizer and real Qt ManagementServer now have native
  socket/fragmentation tests, retaining OFF flags and exact DNS/SNI values while
  rejecting unrelated privileged options. The new suite is required in final
  client-linux CI; no dispatch has been performed.
- `recipes/openvpn/native_dns.py` is a checked/idempotent source overlay exported
  and applied by the existing recipe. Immediately before UP it reports the
  actual native add_routes result as `amnezia_native_routes` (success/failed/
  unmanaged), without changing route execution, scripts, or native return values.
  The client parser accepts route proof only from a complete UP frame with
  exact success; historical runtimes, failed/noexec routes, DOWN and incomplete
  frames provide no proof. This is necessary because native macOS
  CONNECTED,SUCCESS can omit ISC_ROUTE_ERRORS.
- `openvpn-native-route-evidence-overlay-20261124-v1.log` exercises the actual
  do_route function extracted from the complete cached pinned source under
  instrumented OS boundaries: success/failure/noexec/no-routes/no-management,
  checked anchor rejection and idempotence pass. This is isolated native-function
  evidence, NOT an installed OpenVPN runtime/full-protocol acceptance result.
- The first Qt stream-test build failed because its standalone CMake target
  omitted the production client include directory; that target was corrected,
  without changing assertions. `openvpn-management-native-stream-20261124-v4.log`
  records 3/3 passing tests (real Qt server, real service argument sanitizer,
  portable parser). Native DNS suppression/publication and pre-teardown
  restore acknowledgement are still outstanding; this is not transaction
  completion and no production DNS publication was enabled by these changes.
- DNS WFP lease code was separated from the general WindowsFirewall manager.
  It retains the same baseline GUID and priority, local-loopback flag, exact
  IPv4 endpoint and UDP/TCP port-53 conditions. No IPv6 rule was added.
  `windows-dns-recovery-native-wfp-20261124-v2.log`: 14 passed, 0 failed,
  including enumeration of the actual four owned WFP filters.
- Added `tests/native-dns-desktop-lifecycle`, requiring the real service Xray
  runtime/generated header (no C ABI stub). The production service build also
  builds this target with AMNEZIA_BUILD_TESTS on Windows/macOS.
- Existing pinned Windows Xray 1.4.0 source, Go 1.27.1, MinGW and module cache
  were reused offline to build the DNS-enabled DLL. Native MSVC compiled and
  linked ServiceGuard, Windows OS-DNS recovery and the WFP lease against it.
- Initial failure evidence is retained. An incorrectly SkipAsSource-marked
  fixture primary was corrected. A real production readiness defect then
  reproduced: DAD stayed tentative at the hard-coded 2-second deadline while
  GetIpInterfaceEntry reported DadTransmits=3 / RetransmitTime=1000.
  `windows-dns-service-lifecycle-native-20261124-v6-diagnostic.log` contains
  that evidence, matching Microsoft's MIB_IPINTERFACE_ROW documentation.
- Production preparation now creates/journals aliases as a batch and waits
  for every address to be Preferred under one deadline derived from native DAD
  policy, capped at 10 seconds for the whole set. DAD is not disabled; unknown,
  duplicate or over-budget policy fails closed. DNS reply assertions/timeouts
  were not relaxed. This is unrelated to the earlier Mac TCP MTU timing failure.
- `windows-dns-service-lifecycle-native-20261124-v8.log`: all three publication
  crash boundaries pass (5 passed, 0 failed; one parent-skipped child-only slot
  executes in subprocesses). Each uses two distinct aliases for duplicate
  IPv6-only resolvers, real UDP/TCP AAAA NODATA and A SERVFAIL, `_Exit(77)`,
  production startup recovery, modified-journal/external-DNS refusal,
  confirmed restoration before removing both aliases, and repeat startup.
- `windows-dns-service-native-dependencies-20261124-v2.json` compares the actual
  cached and candidate DLL build info: every existing compiled module/version/
  checksum and Go version is unchanged; only first-party nativedns was added.
- After the batch change, real private resolved/D-Bus Linux regression passes:
  `native-dns-linux-after-batch-readiness-20261124.log`.
- These crash boundaries are after a durable DNS snapshot exists. Missing,
  invalid, legacy or unconfirmed ownership/snapshot state remains fail-closed,
  not permission to remove ambiguous aliases.
- Current macOS native guard testing is wired into a new required classic
  macOS build lane for final hosted validation, not executed yet. No local Mac
  runtime testing or current-source CI dispatch/push was performed.
  Installed-service/whole-protocol teardown, OpenVPN/IKEv2/Android integrations
  and final full builds/acceptance remain outstanding; this is not merge ready.
- Global IPv6-OFF packet containment across a service crash and the scope of
  encrypted-endpoint WFP exceptions require separate whole-backend validation;
  DNS startup/alias recovery tests do not establish those guarantees.

User steering: continue all remaining backends, including macOS; unavailable
Apple runners do not block implementation. Do not dispatch/push intermediate
CI runs. Hosted testing is deferred until the backend integration is finished.

The desktop service already links `amnezia-xray-bindings` and therefore already
owns a Go runtime, including when a native WG/OpenVPN/IKEv2 connection is active.
The DNS socket implementation is being integrated into that same archive rather
than a new service helper/runtime. It is split into the small source module
`native/routing/nativedns`; packet dnsguard delegates its unchanged wire policy
there. The isolated module has only the existing DNS codec/x/sys dependencies,
not the routing engine or either gVisor TCP stack.

Local implementation now includes original-interface IPv4 UDP/TCP forwarding,
same-socket UDP retries (three attempts, one-second spacing), slow/spurious reply
handling, cancellation/read join, strict IPv6-upstream rejection, and transactional
preparation of a resolver endpoint set. Missing/broken scope has no default
dialer. The original IPv6-only resolver remains represented and answers local
AAAA NODATA; other questions fail closed.

The checked native desktop Xray recipe overlay adds DNS C exports to the existing
archive and rejects shared-dependency version changes. The actual cached 1.4.0
source compiled offline; an executable C client passed real UDP/TCP NODATA,
IPv6-only SERVFAIL, duplicate admission, joined Stop and stale-handle tests.
Compiled native Xray dependency versions were compared before/after and unchanged.
Evidence: `native-desktop-dns-cabi-client-20261123-v4.log`.
Ten isolated local race repetitions of the new module/session and packet frontend
passed; Windows amd64 and Darwin arm64 Go cross-compilation passed (not local Mac
execution or physical acceptance). Evidence: `native-dns-module-session-20261123-v3.log`.

Remaining immediate integration is the C++ service/OS-settings transaction,
per-resolver assigned-address ownership/recovery, and native adapter callers.
Android native OpenVPN/Xray and Windows IKEv2 lifecycle wiring also remain.
These source/runtime changes are not yet universal product activation.

The full local parent race suite subsequently passed (AWG/WG, engine, mobile,
desktop, DNS, socket policy and the new DNS module), along with dependency
provenance and four checked Apple overlays:
`native-dns-module-parent-full-20261123.log`.

The C++ DNS utility now has a guarded prepare/publish/retire transaction.
Uncertain publication blocks further updates until confirmed restoration;
retirement failures remain owned for retry. An unchanged verified scope can
retain DNS sessions. Linux OFF operations use checked synchronous D-Bus replies
and preserve the original domain snapshot; stale async domain callbacks are
generation-rejected. macOS OFF checks native publication/restoration results and
retains its original service snapshot across updates. Windows retains its
checked native DNS API path. ON uses the legacy platform path.
Six local Qt transaction cases passed, and the production Linux DNS utility
compiled: `native-dns-qt-transaction-20261123-v3.log`. New macOS/Windows C++ SDK
compilation remains pending for final hosted verification, not claimed locally.
The actual service guard factory/assigned-address recovery and adapter call sites
are still to connect; there is no claim that these wrappers are already enabled.
The Go C ABI now supports coexisting prepared/published generations, so a new
endpoint set can become ready without stopping the old published one.
Five checked-overlay Python cases and the real native-archive C client passed
again, including independent retirement/stale handles across both generations:
`native-desktop-dns-cabi-client-20261123-v5.log`.

## Current hosted resource blocker — 2026-11-23

Run `45181826367` at `9d1a3ae` passed every acquired lane, including the new
native DNS assigned-interface fixture. Both required macOS ARM lanes were
cancelled without acquiring a runner, so the aggregate gate is FAIL, not PASS.
One targeted failed-job rerun on the identical source had the same result:
jobs `137750488708` and `137750489268` were not acquired. GitHub explicitly
reports hosted ARM capacity constraints. Annotations for both attempts are
preserved under `ci-9d1a3ae-*-arm-capacity*.json` in the external evidence folder.
No further automatic retry is scheduled, no ARM lane is made optional, and no
local Apple runtime result is substituted. This resource blocker does not close
the outstanding native backend integration work below.

## Native desktop DNS-only socket frontend preparation — 2026-11-23

Native desktop kernel/process backends cannot use a second TUN reader. A
local UDP/TCP frontend is prepared in `dnsguard.NewSocket`, sharing the
packet frontend's exact AAAA/A wire policy while leaving all non-DNS packets
with the native backend. It accepts only a matched, explicitly assigned local
IPv4 listener pair and an explicit scoped exchange; it installs no DNS settings,
routes, TUN, upstream selection or fallback. Both listeners are consumed even
on constructor failure. Cancellation joins handlers, and unexpected listener
exit invalidates the endpoint.

An isolated native-interface experiment showed that link-bound resolver
requests cannot reach loopback; they do reach that interface's own IPv4 address.
The frontend therefore verifies exact, unambiguous local address ownership,
rejects non-local client sources (no recursive service for remote VPN peers),
and has a real SO_BINDTODEVICE UDP/TCP NODATA fixture with a negative loopback
control. The fixture is added to the required isolated Linux TCP job.

The complete dnsguard suite passed ten local offline race repetitions within
2 CPU/4 GiB, including real UDP/TCP loopback NODATA/A/SERVFAIL, listener mismatch
and wildcard rejection, cancellation and unexpected-listener teardown.
Evidence: `native-dns-socket-frontend-20261123.log`. This primitive
is NOT activated in desktop adapters. The updated assigned-interface and socket
suite also passed ten offline race repetitions in the same bounded sandbox;
evidence: `native-dns-assigned-socket-20261123-v2.log` (also includes explicit
non-local peer rejection and local loopback-alias preservation).
Per-resolver settings publication,
original scope, native adapter lifecycle and crash/fail-closed ownership remain
to integrate. It does not close the remaining backend completion requirement.

## Hosted budget/mirror failure correction — 2026-11-23

Correction commit `35fb4c0` passed the complete hosted matrix in run
`45172934409`, including the independent required Linux TCP job, DNS regression
and both Apple recovery pools. This verifies the CI correction, not a causal fix
for the earlier isolated Mac MTU latency failure.

Run `45152767498` at `b20a6ee` did not pass the aggregate gate. Mac Intel's
complete core lane and all twenty targeted MTU recovery repetitions passed
(23 passes of that test including the core suite). The earlier 272.946429 ms
failure remains unresolved; successful repetitions are not a causal fix.

Three required jobs were cancelled, with distinct evidence:

- `client-linux` (`137618102234`) exhausted its 120-minute job limit.
  The WSS/TCP script only started at 12:04:52Z, after nearly 117 minutes of
  preceding work, and was cut off at 12:08:19Z. Logs show live TCP progress, not
  a demonstrated shutdown deadlock. No acceptance PASS is assigned.
- `linux-dns-regression` (`137618102314`) exhausted 15 minutes in apt, selecting
  `us-east-2.ec2.archive.ubuntu.com`; tests never started. Its direct job API log
  is retained as `ci-b20a6ee-linux-dns-cancelled-api.log`.
- Apple ARM recovery (`137618102309`) was never acquired by a hosted runner.
  GitHub reports pool capacity constraints. The required ARM pool is retained.

The WSS/TCP script is moved unchanged to its own required 45-minute job, with
helper hash/source/run evidence separate from the installer build manifest.
The installer manifest no longer implies that this separate test ran there.
Neither test deadlines/assertions nor the existing client build budget change.
DNS setup now uses the canonical Ubuntu HTTPS archive instead of the failed
regional mirror, bounded acquisition timeouts, and always-uploaded setup logs.
Offline YAML/required-gate checks passed; hosted correction results are pending.

## Native Apple Xray DNS activation — 2026-11-23

Run `45141358149` at `7751c9c` passed Apple SDK/full app, native socket binding
and DNS/filter checks, but the overall gate failed: Mac Intel
`TestMaturePathMTUAndTCPRecoveryWorkersRetainTCP` completed the existing TCP
payload in 272.946429 ms after confirmed MTU (limit remains 250 ms). First
resumed byte was at 25.954601 ms. Failed job `137580999053` is preserved in
`ci-7751c9c-macos-intel-failed.log`. This is unresolved, not waived as flaky.
Ten focused Linux race repetitions passed with the unchanged test; that does not
prove the Mac cause. The test now records bounded receiver progress and timeout
counts on slow completion without changing the assertion or logging in its
packet/reader hot path. Three focused Linux repetitions of that instrumentation
passed. New hosted evidence is required; no causal recovery fix is claimed.

The next layer registers the existing DNS controller/filter before publishing
OFF DNS settings, enables interception in the sole HEV reader only for OFF, and
orders teardown as DNS cancellation/join, HEV reader join, Xray shutdown, then
filter and socket-policy retirement. Original resolver order, metadata and
route-derived scope are retained by the same native DNS planner. ON leaves the
HEV interception gate disabled.

The old unretained Swift socket callback is disabled by a checked upstream
overlay. One Go dialer controller owns a handle-scoped underlay policy; updates
with no interface suspend new dials, binding errors propagate, OFF rejects IPv6
sockets, and Stop joins callbacks. There is no provider pointer or privileged
IPv6 DNS path. Xray startup now checks/frees its owned native error result.

Local bounded offline socket-policy race tests (ten repetitions) and four
checked Apple overlay tests passed. Fresh C ABI compilation and DNS/filter
cancellation/retained-host tests also passed, including the new socket bridge in
the archive. Apple SDK/full app and native socket binding checks passed in that
hosted run; activated physical adapter acceptance remains pending.
This is not universal backend completion or physical Apple VPN acceptance.

## Native Xray reader lifetime preparation — 2026-11-22

Run `45058827484` at `9ae44af` passed the complete hosted matrix, including
Apple SDK, public-policy, native DNS/filter and settings-callback tests. Physical
Apple VPN runtime and arbitrary external routing overrides are not proven.

The Apple HEV framework now has checked hooks at its existing sole TUN reader
and readiness boundary. No extra reader/runtime is created. ON has no registered
filter and a C-side disabled gate skips packet callbacks; packets pass unchanged.
HEV Stop is serialized with event-fd
retirement; the real write assertion is retained, EINTR is retried, and no busy
wait can touch a retired fd. The recipe checks required callback references in
the resulting archive so a stale unhooked framework cannot silently pass.

`NativeTunnelRunner` remembers Stop before readiness, sends quit once and joins
the returning reader before completing Stop. Native Xray startup/stop is now
generation-serialized, late settings/readiness callbacks cannot launch a stopped
session, duplicate starts are rejected, and failed startup is cleaned up.
The actual HEV 2.15.0 reader/lifecycle source was cached once for offline overlay
verification. Five Python tests and overlay application/idempotence against that
source passed in the bounded sandbox. Hosted tests additionally build the real
host HEV source from the existing Conan source cache and run its reader with a
socket-pair UTUN fixture, checking readiness, consumption, joined Stop and late
quit after fd retirement. Those tests, Swift runner tests and SDK/full linkage
passed in hosted run `45068248166` at `d6114dd` (complete matrix success);
this fixture is not physical VPN acceptance.

That reader-preparation commit did not register the Xray DNS controller/filter;
the subsequent activation layer above builds on it. Remaining Android/desktop
native adapters are still required before universal AAAA NODATA or merge readiness.

## iPhoneOS public-policy correction — 2026-11-22

Run `45051442590` at `46f425a` failed because `<net/route.h>` is absent from the
iPhoneOS SDK. The earlier bridging-header correction was therefore insufficient.
The failed log is preserved as `ci-46f425a-ios.log`; no private routing structures
were copied and no assertion/compiler check was waived.

RTM_GET and the unavailable include have been removed. DNS paths are now
prepared from the native connection's explicit included/excluded routes,
connected source subnet, public includeAllNetworks/enforceRoutes/local-exclusion
flags, and public getifaddrs snapshots of available underlays. Ambiguous local
interfaces are unavailable, not arbitrarily selected. Forwarding binds the
chosen tunnel or physical interface explicitly, with no default-network retry.
This is public connection-policy selection, not a claim to mirror arbitrary
external administrator routing-table changes. Those edge cases and native
adapter acceptance remain unverified.

Policy preparation runs on the controller's generation queue, so a deferred old
preparation cannot publish into a later session. Changed scopes invalidate DNS
reuse. The pinned native Swift adapter also needs a durable settings-result cell:
its original bare condition signal can lose a fast failure before waiting.
A checked build-tree copy fixes that race without editing the submodule. OFF
also requires confirmed settings and throws on timeout rather than starting
an unconfigured backend. ON routes/configuration and its existing five-second
timeout policy are unchanged.
New tests cover public scope selection and fast/async/missing settings callbacks.
Five local ownership/Swift-overlay Python tests passed offline within the
2-CPU/4-GiB container; new SDK/runtime verification remains pending.

## Native Apple WG/AWG reader integration — 2026-11-22

Run `45046664006` at `670b469` failed iPhoneOS typecheck because Swift's Darwin
import did not expose the routing-message declarations (`rt_msghdr`/`RTM_*`).
The native bridging header now explicitly includes the system `<net/route.h>`;
SDK validation of that correction is pending. The failed job log is preserved,
and its result is not relabelled as an infrastructure error.

The single existing AWG/Xray/routing Go archive now wraps the native `wgTurnOn`
TUN reader with a synchronous packet filter. The pinned upstream ownership entry
is checked before patching; changed/multiple entry points fail the build. Shared
routing is not wrapped. ON has no active filter and native bytes remain native.
OFF registers the Swift DNS controller and rejects IPv6 at that same reader;
non-DNS IPv4, ICMP/opaque native packets and TUN headroom remain unchanged.

The provider prepares/publishes native WG DNS settings through the same
transactional controller as OpenVPN, including adapter settings/path updates.
The filter remains registered across temporary native backend suspension. Stop
first cancels DNS, then joins the native backend, then unregisters/releases the
filter host. Duplicate admission is rejected; unregister joins in-flight
callbacks before host release. Late cleanup uses the original filter lease.
Unchanged DNS is reused during endpoint/settings refreshes instead of resetting
DNS TCP sessions. An OFF settings publication without its callback fails the
connection before the native adapter's five-second proceed-anyway timeout;
late callbacks cannot re-enable that failed generation. Stop also joins already
retiring generations. ON retains its original settings publication path.

Local offline verification passed ten Apple-parent race repetitions of
`dnsguard`, the executable C ABI test including in-flight filter teardown, and
three ownership-overlay Python tests. These used one 2-CPU/4-GiB no-swap
container and existing dependency caches. No packages were downloaded.
New Swift/native filter tests, SDK/full application builds and adapter runtime
acceptance remain pending. Missing native IPv4 interface or original resolver
policy remains a fail-closed unsupported configuration, not silently invented
DNS. Xray and remaining Android/desktop native integration are still outstanding.

## Apple native OpenVPN connection wiring — 2026-11-22

Hosted Actions execution recovered: run `44997772637` at `c2a6e6d` passed all
required jobs. This validates the preceding components/settings tests, not the
connection wiring described here.

Native OpenVPN now calls `NativeDNSController` before publishing its OFF network
settings. Prepared endpoints are staged in the existing packet-flow reader;
ordinary packets retain the native adapter, and the existing IPv6 rejection
remains after DNS dispatch. Publication commits the new generation or rolls back
to the old one. Retired/failed/stopped capture addresses cannot fall through to
the native backend. Normal disconnect, fatal errors and explicit Stop tear down
guards and their operations. ON keeps original DNS settings and routing.

IPv4 forwarding resolves the original server's selected kernel route with a
bounded local RTM_GET request and requires that exact tunnel or currently
available underlay interface. No route/default-network fallback exists. The
kernel lookup runs outside the guard callback queue and cannot revive a
cancelled operation. IPv6 resolver bindings remain unavailable, with local AAAA
NODATA and SERVFAIL for other queries. There is no privileged IPv6 exception.

New hosted tests cover actual Darwin loopback route lookup and controller
prepare-before-publish, per-server separation, IPv6-only upstream rejection,
publication rollback, Stop racing a late settings callback, native packet
passthrough and unchanged ON. SDK compilation and those tests are pending.
This is not physical Apple VPN runtime acceptance or universal-backend support.
Apple native WG/AWG, Xray and the remaining Android/desktop native paths still
need connection integration and adapter-level acceptance.

## Hosted validation unavailable — 2026-11-21

Source `f234c59` adds the per-resolver settings planner and hosted regression
steps; `b7d0517` adds strict IPv4-only OFF upstream validation. Neither revision
has a hosted validation result. A manual dispatch of `sing-box-routing-ci.yml`
was rejected by GitHub with HTTP 422:
`Actions has been disabled for this repository.`
The repository Actions permissions endpoint simultaneously returned
`{"allowed_actions":"all","enabled":true}`; the workflow itself was `active`.
The reason for this external discrepancy is unknown. No Actions policy, account
setting or billing setting was changed. Earlier `11949e6`/`2180e7f` results do
not validate these newer revisions. Apple SDK/runtime checks remain blocked
until hosted Actions execution is restored. Universal native DNS integration
and merge readiness are still incomplete.

## Per-resolver native DNS settings — 2026-11-21

`NativeDNSSettings.swift` prepares a connection-local copy with one IPv4 DNS
capture address per original resolver, preserving order, duplicates, domain
scope and search metadata. Only individual capture /32 routes are added; native
IPv4 routes/settings and the original settings object are not modified. Specific
route/address collisions fail closed; encrypted DNS is not silently downgraded.
IPv6 upstream bindings remain unavailable, while retaining a local endpoint for
AAAA NODATA. iOS 26/macOS 26 resolver failover to the system is disabled.

Resolver paths must be supplied explicitly by the native owner. Apple documents
that system routes and interface scoping supersede included/excluded routes:
https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic
The planner therefore does not guess the DNS scope from a default route or move
all split DNS through the tunnel. Establishing the original scope and publishing
prepared guards transactionally with packet dispatch/teardown are still pending.
The initial planner requires a native IPv4 interface; IPv6-only native interface
capture setup remains to integrate. SDK/settings regression tests are pending.

## Strict IPv6 OFF clarification — 2026-11-21

The user clarified that OFF means all IPv6 traffic, including DNS upstream
transport. The proposed privileged IPv6 native DNS control path was abandoned;
its uncommitted Go prototype and source-binding change were removed. Its local
test logs are historical prototype evidence, not shipping-code acceptance.
No such exception was committed or enabled.

Native DNS integration must use an IPv4 managed endpoint for local AAAA NODATA.
An original IPv6-only upstream is unavailable with OFF; other queries must fail
closed without silently substituting a resolver or underlay path. An existing
multiple-server policy may retain its original explicit selection semantics.
The earlier control-plane preservation requirement below is superseded.
The OFF-only Swift resolver now rejects IPv6 literals (including scoped and
IPv4-mapped forms) before creating an operation, and also rejects hostnames,
unspecified/multicast/reserved IPv4 destinations and NUL-truncated input. New
resolver validation tests are pending Apple SDK execution. ON is unchanged.

## Scoped native DNS transports — 2026-11-20

At `2180e7f`, hosted iOS job `136366795882` passed the iPhoneOS
typecheck, executable Swift/native host test, actual loopback UDP/TCP transport
tests and full app/packet-tunnel builds. The first matrix attempt was not green:
the two macOS ARM jobs never acquired runners (capacity annotations, no steps).
Only failed/uncompleted jobs were resubmitted after inspecting those annotations.
The second attempt also failed to acquire both ARM runners: jobs `136411407621`
and `136411408425` were cancelled without steps, with the same capacity
annotations. The build gate correctly failed; no third rerun of the same code
was requested. The successful iOS job log is preserved locally as
`ci-2180e7f-ios-fetch2.log`; an earlier log-fetch attempt failed at the blob
endpoint and is not a product-test failure. No application packages were fetched.

The transport fixture now also checks idempotent cancellation for both UDP and
TCP after the server receives the query, spanning the retry and deadline windows
and asserting no late callback or reopened connection. This additional test has
not yet run with the Apple SDK.

In `44744543451` at `49d1819`, the new iPhoneOS host typecheck, C client and
executable Swift/native DNS lifecycle test passed. Full iOS app construction
subsequently failed fetching OpenVPNAdapter: GitHub:443 was unreachable for
75 seconds. Windows build job `136317552765` lost runner/server communication
while its build step was in progress; no failed product assertion was reported.
Those failures are retained, not converted into complete package passes.

`NativeDNSResolver.swift` now supplies explicit tunnel/interface/loopback
transport scopes, numeric server validation, same-connection bounded UDP
retries and TCP framing/candidate replies. Legacy through-tunnel APIs remain
only for older OS versions. It does not select another resolver/interface on
failure. Host dispatch now keeps an absolute monotonic deadline across its
queue instead of restarting the timeout after queue delay.

The hosted tests use a loopback-only ephemeral UDP/TCP fixture for first-packet
loss, same-socket retry, fragmented TCP framing, multiple candidate replies,
timeouts and non-query non-retransmission. The original SDK and transport tests
passed at `2180e7f`; these factories still are not invoked by native connection
settings/lifecycles.
Original DNS-route mapping and IPv6 DNS control-plane handling must be completed
before universal NODATA or merge readiness can be claimed.

## Swift native DNS host layer — 2026-11-20

Run `44734415980` at `b0cbffc` passed the complete main matrix, including the
Darwin native DNS C client. The next layer is `NativeDNSGuard.swift`: it owns
the asynchronous host callback boundary, classifies packets without a second
reader, preserves per-query UDP/TCP selection, rejects immediate scope failures,
keeps spurious replies from terminating valid pending work, and cancels requests
before native host release. iOS/macOS targets include the class but no native
connection path instantiates it yet.

The C API gains terminal request rejection so native errors become SERVFAIL
without copying exception messages or waiting for a timeout. Go/C regressions
and a new executable Swift/native-host lifecycle test cover that path. SDK and
Swift runtime validation of this layer remain pending; concrete native DNS
transports, settings publication and protocol lifecycle integration are still
required. This is not universal-backend completion or a merge-readiness claim.
The updated Go/race suite passed ten Apple-parent repetitions and the executable
C client passed locally with rejection coverage. No packages were downloaded.
The Apple Conan recipe now requires the exact new exported text symbols, so
missing native-DNS ABI cannot be mistaken for a compatible archive.

## Native DNS C-client portability follow-up — 2026-11-20

Run `44726482222` at `b573b00` passed every executed lane except the iOS
construction lane's new C-client compilation. The iPhoneOS unified archive,
all new DNS symbols, Swift policy typechecks and the original host packet-flow
ABI test passed before that failure. The C client's Linux-oriented
`_POSIX_C_SOURCE` hid BSD typedefs used by Darwin `resolv.h`; it now requests
the Darwin feature namespace on macOS, retaining the POSIX namespace on Linux.
`-Wall -Wextra -Werror` and all test assertions remain unchanged.
Hosted execution of the corrected native DNS C client is still required.

## Universal AAAA NODATA requirement — 2026-11-20

The user explicitly chose AAAA NODATA for **every backend** when IPv6 is OFF;
native Apple DNS omission is not an accepted limitation. This newly confirmed
criterion blocks merge despite the fully green `8679f05` baseline. The design
and remaining integration work are in `IPV6-OFF-DNS.md`.

The first shared primitive is implemented in `native/routing/dnsguard`.
In-memory packet tests cover UDP/TCP over IPv4/IPv6, local AAAA NODATA without
upstream traffic, scoped A forwarding with transport preservation, failure
without fallback, cancellation and teardown. The native TUN wrapper preserves
non-DNS bytes/headroom and keeps managed AAAA packets out of the original
backend. Ten race-instrumented repetitions passed in one offline 2-CPU/4-GiB
build container with swap disabled. It is **not connected to a shipping native
backend yet**, so universal support and merge readiness are not claimed.

The asynchronous native-exchange bridge and Apple C exports now have ownership
and cancellation coverage. A real C client passed NODATA/scoped forwarding,
passthrough classification, exactly-once completion/release and late-reply
rejection against an archive using the pinned Apple parent Go graph. Initial
offline preparation found the Apple gVisor pin missing from one cache; it was
reused from the existing integration cache without downloading anything.
An unrelated non-Apple header unused-parameter warning was corrected without
weakening `-Werror`. Dependency verification, ten Apple-parent race repetitions
and the ordinary dnsguard/engine/mobile suites passed. The new CI checks use the
actual unified Apple host library and archive symbols. SDK validation, Swift
native-adapter wiring and the other native backends are still outstanding.

No new artifact downloads were made. Existing arm64/x86_64 packages from
`44702509917` (source `8679f05046c55561b76aad7697059988193c3247`) passed local
hash/size/ABI/payload/notice verification for eight APK entries. The report is
explicitly partial; armv7/x86 and desktop/iOS artifacts were not locally
re-audited after downloads were stopped. The all-green hosted source baseline
is main `44702516775` and Android `44702509857`, not evidence for this new work.

## Atomic application-policy DNS replacement — 2026-11-20

Android run `44698056095` at `697a9a8` failed WG/API29 package-reinstall recovery
and an independent WG/API35 cyclic UDP probe; other lanes passed. The retained
API29 snapshot distinguishes history from present state: `dns_available=true`,
`dns_version=2`, three completed/failed queries with last class
`generation-unavailable`. The bounded live log contains no recovery request
or underlay change. Generation 1 is initial publication; the application-policy
update reserves generation 2. This narrows the DNS failure to that update's
freeze-before-build interval, not permanently suspended network recovery.
It does not establish a cause for the separate API35 UDP timeout.

`Runtime.UpdateAndroidApplications` now reserves a replacement generation
without dropping the current DNS/policy. It builds the candidate and atomically
publishes UID membership plus fresh DNS through the existing `replaceWith`.
A failed build retains the old policy; a real network suspension increments
the version, invalidates the candidate and remains fail-closed. Application
updates cannot reopen already-suspended DNS. Network-DNS reload/suspension
behavior is unchanged.

The complete Go engine and mobile suites passed locally. Three deterministic
boundary cases cover successful commit, candidate-build failure and real
network suspension; the new test passed 20 repetitions. A separately retained
red-control source copy restores the old freeze-before-build behavior and
fails specifically at the existing-DNS preparation boundary. The fixed source
and red copy were not conflated. These checks ran in one offline Linux build
container capped at 2 CPUs / 4 GiB total with swap disabled; the Android
emulator was stopped. Race checks and current-source hosted Android acceptance
are still pending. No complete Android pass is claimed.

## Current hosted baseline and recovery evidence — 2026-11-20

At `b56b53f`, main run `44583629056` passed the entire matrix, including both
ARM Mac jobs. Linux-native run `44583629145`, current Android packages and all
other listed supporting workflows passed. Android acceptance `44583612049`
passed 5/6 lanes; AWG/API29 failed after application reinstall and capture
restart in the personal profile. Earlier work-profile failure is retained.
This establishes a repeated restart scenario, not its underlying cause.

The retained diagnostic `dns_last_failure=generation-unavailable` is historical
and does not establish current availability. The snapshot now includes current
generation availability/version, with tests covering both suspended DNS and
republished DNS retaining the historical failure label. Recovery logs retain
only handle/ticket counters, stage and exception class, never profile values,
endpoint names/addresses, credentials or exception messages.

The final logcat snapshot in the latest failure retained only teardown events:
its count limit can lose early selected events amid unrelated system logging.
A targeted live log now starts after adb root, with a 10,000-matching-record
bound, records premature exit, and is terminated/reaped in finally. The file
is explicitly included in the primary artifact allowlist. The existing final
snapshot remains. These are evidence changes only, not a claimed DNS fix.
Hosted validation of the new diagnostics remains pending; no local Go/Kotlin
PASS is claimed. Merge readiness is still blocked by Android recovery, native
Apple AAAA NODATA acceptance and current-source final artifact reconciliation.

## Linux hosted closure and Android capture review — 2026-11-19

Run `44581190296` at `48387b4` passed all six required Linux-native lanes:
AWG/WG namespace capture on Ubuntu 22.04/24.04 and both system-resolver
split-DNS lanes. This validates the pipe-draining harness correction in the
previously failing workflows; their earlier failed evidence is retained.

New Codex finding `4632863609` identified IPv6-OFF capture loss in Android
destination include mode: split compilation removed the /1 capture routes.
The builder now records the explicit full-family capture requirement and
installs it after destination split compilation, stripping IPv6 exclusions
while retaining IPv4 split policy. Protocol setup records the requirement
before its no-split/disabled-split early returns. Missing preference/ON still
uses the existing destination scopes. New JVM regressions cover IPv4-only
include and IPv6 include/exclude policies under OFF.

Local Gradle attempts hit the 4-GiB laboratory cgroup limit, including after
reducing guest allocation to reserve build overhead; no local Kotlin PASS is
claimed. Limits were not increased and no second VM ran. The emulator was
OOM-terminated; its stale lock files were preserved under
`.before-merge-prep-oom` before retry. Hosted Kotlin tests and actual Android
packet acceptance remain required for this correction. No merge is authorized
by this readiness checkpoint.

## Merge preparation: Linux helper shutdown — 2026-11-19

Both Linux acceptance drivers waited for helper exit without draining its status
pipe. The helper emits periodic status on the same select-loop thread that
consumes `stop`; a full stdout pipe can therefore prevent it from reading stop.
The drivers now use `communicate` to deliver stop/EOF and drain output together.
The original 15-second bound, zero-exit assertion, and distinction between
graceful stop and command-pipe-loss abort remain unchanged. No production
networking or acceptance assertion was relaxed.

Five real-process/pipe tests passed in the single constrained API29 laboratory
container (2 CPUs, 4 GiB total memory including emulator overhead, swap disabled).
The negative control fills a 4-KiB pipe: the old wait times out, then draining
allows the exact same process to finish. Tests also check graceful stop, EOF,
nonzero exit rejection and timeout rejection. This reproduces a harness failure
mechanism; the complete hosted Linux lanes must still establish whether it
accounts for their previously retained failures.

Android run `44543994486` at `cf7cf31` passed 5/6 lanes. The remaining AWG/API29
failure is work-profile package-reinstall recovery; the personal-profile case
passed. Its new network-event snapshot shows VPN networks 104 -> 105 while
Wi-Fi underlay 100 stays unchanged. TCP refusal/DNS timeout and
`generation-unavailable` remain observations, not a proven root cause.

Main run `44534261050` at `489318b` has now completed: iOS compilation, Linux,
Windows, Android build/core lanes and Intel Mac checks passed. The only
non-success test jobs were ARM Mac core and TCP recovery (`135596073712`,
`135596073944`): both had empty runner names and no steps. GitHub annotations
explicitly report “The job was not acquired by Runner of type hosted even after
multiple attempts” and macOS arm64 capacity constraints. This establishes an
infrastructure cancellation, not a successful ARM check or a product failure.
The final build gate correctly remained red. Android and Linux-native failures
in the separate workflows below remain unresolved.

## Hosted failures at `489318b` — 2026-11-19

Android run `44534249506` failed three lanes; logs and all six artifact bundles
are retained separately from successful evidence. WG/API35 timed out receiving
VPN UDP during session 94 of cyclic acceptance. WG/API29 reached the personal
application TCP probe but got ECONNREFUSED; its snapshot also reports two DNS
failures with last classification `generation-unavailable`, not an established
cause for the TCP refusal. AWG/API28 passed its ordinary compatibility test,
then timed out uninstalling the instrumentation APK before OpenVPN testing.
No OpenVPN packet failure is established by that setup timeout.

The network-events snapshot added earlier was omitted from the main acceptance
artifact allowlist (the other subdirectories upload all logs). The allowlist
now includes that exact non-fixture log. This repairs evidence retention only;
none of these acceptance failures is claimed fixed or retried unchanged.
The separate Linux native run `44534261084` also failed: inspected namespace
and AWG system-resolver jobs timed out waiting for child shutdown; a WG
system-resolver job failed uploading artifacts. Other failed namespace lanes
still need individual inspection. Main app/iOS compilation was still running
at this checkpoint. Subsequent local tests must use one 2-CPU/4-GiB VM.

## Codex review follow-up — 2026-11-19

Run `44525956279` at `9cbc7f0` passed every required lane except the iOS app/
extension compilation. The SDK diagnostic identifies an incorrect override
parameter type in the new native capture guard: the superclass accepts
`NETunnelNetworkSettings?`, not `NEPacketTunnelNetworkSettings?`, with a
Sendable completion handler. The override now matches that signature and
conditionally casts packet settings before applying capture; nil/base settings
are forwarded unchanged. A new hosted build must validate the correction.
The previous Intel TCP timing failure did not recur; its cause remains unclosed.

The four findings against `057b7a5` were confirmed by inspecting their real
call paths. Android DNS overrides now precede installation of the global AAAA
NODATA rule, retaining FakeIP priority; the complete Go engine suite passed
locally with `with_gvisor`. Linux Xray establishes service TUN ownership before
launching tun2socks, rather than adopting an existing interface after STACK
readiness. Apple OpenVPN receives the explicit preference and retains full
IPv6 capture without site/provider exclusions when blocking; the transport
endpoint remains exempt.

Native Apple WG/AWG now receives the preference outside the shared-routing
conditional. Explicit OFF removes IPv6 AllowedIPs and site exclusions from
the backend configuration, while every adapter network-settings publication
retains full IPv6 capture (including legacy profiles without an IPv6 address).
The sanitized configuration is also the saved endpoint-recovery configuration.
Missing preference still defaults ON; shared routing retains its existing policy.
New Swift tests cover policy/default selection, backend prefix filtering,
full capture, endpoint preservation, repeated settings and IPv4 preservation.
These Swift/Apple SDK tests and the real Linux Xray path still need hosted
verification; no local Mac runtime or physical iOS acceptance is claimed.
Native WG does not use the shared DNS interceptor: its AAAA NODATA behavior is
not established by the peer/capture fix and remains a separate acceptance gap.

Run `44510562002` completed with Linux (including production IPsec update),
Windows, iOS and Apple TCP recovery passing. Its remaining failure is Intel
`TestMaturePathMTUAndTCPRecoveryWorkersRetainTCP`; the failed log is retained,
and its cause is not yet established. Android run `44510551649` passed all
six lanes; this alone does not close the earlier intermittent API29 TXT failure.

## IPsec registry pin repair — 2026-11-19

Run `44501519812` at `cfc66f0` preserved the missing reason: all standard
container preflight fields matched, but Docker failed at `FROM` because OCI
index `21f2a1b28dbbe69c4331571941df548eee2f4e1cba16af8b161248d66db8d490`
is no longer registry-resolvable (`manifest unknown`). No cutover occurred.
The same digest failure was independently reproduced with registry access.

The replacement is OCI index
`78ea73fb726bc97ccb8c592df88030fe44cb962bdd8cb6cd4da53630bc199374`.
Registry bytes, child manifests and configurations were hash-verified for
amd64, arm64 and arm/v7. All three advertise revision `5ff51748` and Libreswan
5.4.2. The genuine upstream commit is
`5ff51748cd5889072fd0ee5da55262d779441de5`; its Dockerfile declares the same
version. The amd64 image was pulled by digest and executed without network,
capabilities or a writable rootfs: `ipsec --version` returned `Libreswan 5.4.2`.
ARM execution is not claimed. No mutable-tag fallback or TLS bypass was added.
Hosted update/rollback and unchanged-client packet verification remain pending.
As with any third-party pin, continued registry retention is externally owned.
Android artifacts now also retain the selected network callbacks via a final
logcat snapshot, avoiding loss when initial `adb root` restarts adbd. This is
additional evidence collection for the unclosed API29 TXT failure, not a DNS fix.

## Hosted follow-up at `cd99b32` — 2026-11-19

Android run `44491504894` passed both complete API35 lanes, both API28 lanes
and AWG/API29. The strengthened OpenVPN scope regression passed in hosted CI.
The remaining WireGuard/API29 failure is the initial personal-profile TXT
request (`uid=10148`), before managed-profile acceptance begins. Preserved
diagnostics include `generation-unavailable`; the precise triggering event is
not proven. The unchanged, hash-verified hosted `cd99b32` APK subsequently passed
both personal and managed profiles locally, including a cold-start experiment.
No DNS behavioral correction or final Android green-gate claim is made.

Main run `44491513666` completed its Mac ARM/Intel, Windows, iOS and Android
lanes successfully. Linux stopped at the production SSH IPsec test: the forced
post-cutover failure expected `rolled_back`, but received an earlier `rejected`.
The updater redirects its reason to a transaction log that was lost when the
owned nested daemon was removed. The lab now emits bounded, credential-redacted
transaction output and a non-secret preflight snapshot on an unexpected result,
before preserving the original assertion. Two diagnostic-safety tests pass.
This is diagnostic preservation, not an IPsec fix; the original failure remains FAIL.
PR remains draft; source/package reconciliation still depends on the final gates.

## OpenVPN final-route publication — 2026-11-19

In the single owned API28 VM (laboratory total limited to four CPUs and 8 GiB,
no swap), the unchanged hosted APK from merge source
`6dc7c3479fc02aac89ef360ecbfcab47eff797e0` reproduced the IPv6 scope failure
after the AWG compatibility prelude and repeated OpenVPN scope transitions.
The original socket used NATIVE; three fresh diagnostic connections one second
apart then used VPN without changing routes. Bounded header-only metadata
confirmed the initial native loopback path and later `tun-ovpn3test` ingress.
The original assertion remained FAIL.

Android 9 primary source confirms that the LinkProperties getter can expose
the new snapshot before netd finishes installing routes, while the callback
follows route installation. The correction waits for publication of the final
TUN's complete addresses/routes before returning its descriptor to OpenVPN.
It rejects stale-agent/intermediate-interface observations, closes the TUN on
failure and supports disconnect cancellation. It does not bind test sockets,
flush caches, add synthetic addresses or alter IPv6 scope/server capability.

The final local JVM-dex prototype passed the AWG prelude plus all 32 IPv4-only
and 24 dual-stack cases: eight scope cycles, eight independent TCP probes per
destination, UDP, loopback and both original IPv4 streams (2016 IPv6 assertions).
Six publication-state and five protocol-policy JVM tests passed. All non-dex
payload bytes were verified identical to the hosted APK. This is explicitly a
local prototype, not a production package from a pure source commit. Hosted
source-coherent APK acceptance is still required.

A rejected capture-source prototype passed its IPv4-only cases but failed a
later dual-stack case. Its patch/artifact/failure evidence remains preserved;
none of its synthetic-address code is retained in production.

## Retained Android socket attribution — 2026-11-18

Follow-up run `44350559015` at `a2f4a62` passed both complete API35
lanes (including retained TCP), both API29 lanes and WireGuard/API28.
AWG/API28's shared-core compatibility step also completed, but its subsequent
OpenVPN IPv4-only `stale-full` case failed: `fd99::4` returned `NATIVE`.
The live snapshot contains a `tun0` unreachable IPv6 default and UID 10088
capture rule, yet the offending TCP socket used native source `fec0::…`
and mark `0x40065`. This reopens the scope-change/cache failure described in
`scripts/routing/android-openvpn/README.md`; the previous passing runs do not
establish its elimination. No cache flush, forced VPN binding of native-scope
probes, blind rerun or acceptance relaxation is an approved fix. Final Android
acceptance and PR readiness remain blocked.

Run `44346633233` at `9b97207` passed five of six lanes. AWG/API35
failed during retained warmup with session 107 still alive, no capture refresh
and no pending/failed DNS. Preserved pre-cleanup Android events show cellular
network 209 becoming inactive at 16:31:30.915, then Netd destroying one socket
for that netId at 16:32:00.914; the Java abort followed at 16:32:01.990.
The surviving media socket carried Wi-Fi netId 100. This implicates test-owned
sockets inheriting different underlay netIds under the VPN-owner UID.

The retained shared-core probes now explicitly bind each original socket to
the VPN Network identified by its capture address before connecting. There is
no reconnect, process-wide binding, timeout increase or observer relaxation.
OpenVPN split-scope probes remain implicitly routed. Hosted verification is
still required; this is not a final acceptance or PR-readiness claim.

## Android DNS stall investigation — 2026-11-18

Run `44326437543` at branch source `9ace22a` passed five Android lanes.
AWG/API35 failed with two real-DNS requests still pending for 4001 ms before
the application TCP connect timed out; the peer did not receive its TCP SYN.
This establishes a pre-connect DNS stall, not a slow Android owner lookup.
The exact location of the original lost/stalled DNS reply is not yet proven.

A deterministic real-UDP-socket regression drops the first DNS datagram:
the pinned UDP transport does not retransmit and reaches the caller deadline.
The shared-core UDP decorator recovers by issuing at most three copies over
the same transport, one second apart. The original attempt remains valid;
first DNS reply wins, including NXDOMAIN/NODATA. Caller cancellation/deadline,
resolver selection and path are preserved; non-query operations are not retried.
The full local Go engine suite and focused real-socket/retry regressions passed
without QEMU or Android emulators. Hosted APK acceptance of this correction
is pending; no final green-gate or PR-readiness claim is made.

## Hosted continuation — 2026-11-17, final gate still open

The user subsequently authorized push, PR updates and hosted Mac checks.
Local Mac execution remains excluded. PR #18 remains draft; no merge is
authorized. The dated local checkpoint below is historical, not current CI status.

- Native Darwin production Qt route adapter: run `44073792451`, source
  `941715d011fd52e52ec7c7915d3b7263d964a545`, PASS on macOS 26 and macOS 15 Intel.
  Original TCP survives A→B→A; new TCP/UDP use the selected paths; exact TCP
  accept counts are A=2/B=1 and owned TUN cleanup passes. This is not full
  production OpenVPN integration or physical network handover acceptance.
- Main run `44142519288`, source
  `ca9fb945aa3ae4f6c4209b0aff71efa4a1f43353`: Linux client lane PASS, including
  production SSH IPsec update/rollback with unchanged independent strongSwan
  client traffic and subsequent Linux acceptance. Production IPsec now pins
  upstream OCI index `21f2a1b28dbbe69c4331571941df548eee2f4e1cba16af8b161248d66db8d490`
  (revision `f48cd8db`, checked amd64 Libreswan 5.4.1).
  Overall first attempt FAIL: Intel Apple TCP recovery took 439 ms against
  the unchanged 250 ms bound; ARM jobs were cancelled. Failed evidence is retained.
- Android run `44153915121`, source
  `8d232fc`: both API28 lanes and AWG API29 PASS after correcting shell scope.
  WG API29 app-policy and both API35 full lanes FAIL. API35 fails during
  reconnect cycles with missing TCP/UDP responses; these are unresolved failures,
  not successful retries or physical-device results.

Hosted artifacts and later source fixes do not relabel the local `93aef02`
packages below. Final full-gate success and artifact reconciliation are pending.

## Default-on IPv6 preference — local acceptance, 2026-11-16

The user removed historical OpenCode/Telegram incident attribution from the
completion requirements and requested a default-on IPv6 switch on every
platform. This is new product work, not covered by the earlier checkpoint.

The preference is stored separately from server capabilities, included in
backups, defaults to ON for old installations/backups, and applies on the next
connection. OFF must retain capture and reject IPv6 rather than create a native
bypass. The shared AWG/WG compiler rejects captured IPv6 before app/destination
rules and returns AAAA NODATA while retaining IPv4 DNS. Android and Apple NE
session builders pass the preference even when split DNS is configured.
OpenVPN, Xray and native desktop WG paths have corresponding connection-local
policy changes. Native Windows IKEv2 uses an independent dynamic WFP policy
when OFF; its IPv6 RAS default-gateway option is enabled when ON.

macOS OpenVPN dynamic-host capability is now source-enabled as requested, with
the existing Darwin adapter. No Apple SDK/native execution is claimed.
macOS tests remain excluded by the user's explicit decision.

Production package source is `93aef020f0ae6ff610d98a9cd5ecd50ddd2eb52d`;
Android acceptance harness is `66993d8e15660e47de74fd6b4a9172f888b4f859`
(test-only addition, not a package rebuild).

Locally executed checks:
- Four ordinary Android debug ABI packages: signatures, 16-KiB alignment,
  native pins/notices and Qt payload binding PASS.
- Actual x86_64 APK on API35, AWG and WireGuard: default/explicit IPv6 ON,
  OFF AAAA NODATA, cached FakeIP/ULA/NAT64 TCP+UDP rejection, IPv4 VPN/DIRECT
  preserved and independent observer counters unchanged.
- Full Android AWG and WG acceptance PASS, each including 100 connection cycles,
  old interactive/media TCP recovery, aged upload MTU, live per-app DNS/routing,
  IPv6 scope and always-on/lockdown. These are emulator, not physical-device or
  battery results.
- Linux ordinary IFW installer, 32 Qt targets, and installed-service acceptance
  on Ubuntu 22.04/24.04 PASS. Each installed run includes 100 resolver cycles,
  endpoint migration, AWG/WG preserving recovery with strict policy on/off,
  helper crash recovery and OS-state restoration.
- Installed Linux OpenVPN matrix PASS: full/include/exclude, legacy/API and
  stale-capability cases with original IPv4 TCP retained.
- Windows ordinary MSI/EXE builds, 31 Qt targets, actual installed-service
  acceptance and uninstall PASS for both installer formats.
- Windows installed OpenVPN full/include/exclude, API, legacy and stale-capability
  canonical gates PASS. Include route-preservation and the independent native
  IPv6 preference gate PASS: OFF survives KillSwitch disable, IPv4 remains
  usable, IPv6 is restored after policy removal.

Earlier failed attempts are retained separately, not overwritten: a WG fixture
without native DNS 1053, Linux export-mode/probe packaging omissions, and Windows
fixture IPv6/guest-clock setup failures. TLS validation was not weakened.
The original WG run changed CPU limits mid-run and is not performance-parity
evidence. Final AWG/WG retries used the stable reduced resource budget.

Apple SDK/native execution remains NOT RUN; no claim of native macOS/iOS
acceptance or a newly built Apple package is made. End-to-end IKEv2 negotiation
and physical-device handover are not established by the independent WFP gate.
No push, hosted CI, PR-ready transition or merge was performed.
Earlier artifact/checkpoint sections below are historical and retain their
original source attribution. Final artifact reconciliation is tracked separately;
local green results do not authorize publication or removal of PR draft.

## Historical pre-preference continuation — 2026-11-16

The current task excludes testing on macOS by explicit user decision. Missing
macOS execution is therefore not a blocker for this task, but remains **NOT RUN**,
not a successful native check. At the checkpoint below, desktop OpenVPN dynamic
IPv6 updates on macOS were disabled; the Darwin adapter had not been compiled with the Apple SDK
or validated against the kernel. Portable policy tests on Linux do not establish
either result. Apple and physical-device results below are historical and must
not be applied to the current source.

Current source checkpoint: `2f6f36d791b1eec1bc9cc374ef3df197f87f7d44`.
The Linux Go suite with `with_gvisor`, the full race suite using the existing
race-only dependency preparation, and `go vet` passed using Go 1.27.1.
The current Linux Qt routing build and its two CTest targets passed, as did the
three Python regressions for Android host compatibility and evidence validation.
These are source regressions, not newly built application packages.

Available ordinary artifacts retain their original provenance:

- Android: all four ABI APKs at `7795b41`; complete AWG/WG 100-cycle acceptance
  remains attributed to `9a64032`, with backend byte-equality and focused later
  APK acceptance recorded separately.
- Linux: installer at `7795b41`; installed-service acceptance on Ubuntu 22.04
  and 24.04 includes 100 resolver cycles and 12 OpenVPN cases on each.
- Windows: MSI/EXE at `4bcde28`; both installed-service checks and uninstallation
  passed. Native OpenVPN acceptance covers ten profile cases, 80 TCP/UDP probes,
  six retained TCP connections and foreign-route ownership. The independent
  100-cycle helper run belongs to earlier `dbff27f`, not these installers.

Historical OpenCode/Telegram failures are not causally resolved by synthetic
fault tests. No release, push, PR-ready transition or merge is established by
this checkpoint. The full-plan audit is still in progress.

## Continuation — 2026-10-27

Production source `d64d8af796602ace13cc971df9c19b05615fd2da` fixes the review's
AWG 3.1 persistent-keepalive regression. Desktop, Android and iOS preserve
range strings such as `25-35`; the shared core validates using the pinned AWG
parser and accepts older numeric JSON. Regression tests cover JSON/UAPI
round trips, actual device range retention, desktop profiles and mobile preflight.
All local Go packages passed with `-race`; module verification also passed.

The [full platform matrix 40497706736](https://github.com/StannisMod/amnezia-client/actions/runs/40497706736)
passed all 20 jobs, including the installed Linux/Windows packages, all four
Android ABIs, unsigned iOS, three race-test hosts and eight cross-compile lanes.
[Windows native acceptance](https://github.com/StannisMod/amnezia-client/actions/runs/40497706686)
and [Linux performance comparison](https://github.com/StannisMod/amnezia-client/actions/runs/40497706626)
also passed.

The first independent Linux capture run timed out during reconnect stress;
the first Android emulator run passed 100 reconnects but timed out on the
subsequent legacy AWG transition. Both original attempts remain **FAIL**.
Without production changes, [Linux attempt 2](https://github.com/StannisMod/amnezia-client/actions/runs/40497706716/attempts/2)
and [Android attempt 2](https://github.com/StannisMod/amnezia-client/actions/runs/40497706698/attempts/2)
passed their complete suites. The timeout causes are unresolved; these passing
repeats do not establish that the intermittent failures are fixed.

The independent installed-Linux diagnostic was still pinned to historical
package run `39966881951`. Its source-equality guard correctly rejected the
new production source before acceptance ran. CI commit `0fddbfa` replaces the
pin with selection of a successful package with identical production sources,
retaining manifest-source, SHA256 and source-diff checks without substituting
the packaged helper. The independent repeat
[40505160583](https://github.com/StannisMod/amnezia-client/actions/runs/40505160583)
**passed** with the current package and matching production sources.

The feature remains opt-in and experimental; the physical-device, signed iOS
and other acceptance boundaries recorded below remain in force. PR #1 is ready
for review; it has not been merged or released.

## Continuation — 2026-10-23

Actions were re-enabled by the repository maintainer. The current production
source is `5fd7a8e0ce7a91455a971e61b11688b281815216`; later commits update CI
provenance and documentation. **The full build gate passed**, including all
20 jobs of [39966881951](https://github.com/StannisMod/amnezia-client/actions/runs/39966881951).
The table below supersedes the historical
checkpoints retained after the separator.

| Gate | Current evidence |
| --- | --- |
| Core race tests | **PASS**, Linux, Windows and macOS, [39966881951](https://github.com/StannisMod/amnezia-client/actions/runs/39966881951) |
| Core cross-compilation | **PASS**, all eight architecture lanes in the same run |
| Android APK compilation | **PASS**, arm64-v8a, armeabi-v7a, x86 and x86_64 in the same run |
| iOS app and Network Extension | **PASS**, unsigned compilation in the same run; signed runtime remains untested |
| Linux client and installed package | **PASS** in the same run, including 26 Qt tests, all 61 dependency notices, 100 system-resolver reconnects, resolver reset repair, strict Kill Switch toggles, application scope, IPC reconnect, helper crash/recovery and exact DNS/route restoration |
| Independent Linux package repeat | **PASS**, [39972050403](https://github.com/StannisMod/amnezia-client/actions/runs/39972050403), matching package SHA256 and production source; installed helper was not replaced |
| Windows client, MSI and EXE | **PASS** in run 39966881951, including Qt regressions, installation, actual LocalSystem service acceptance, dependency notices and removal for both installer types |
| Android emulator policy and 100 reconnects | **PASS**, [39972740869](https://github.com/StannisMod/amnezia-client/actions/runs/39972740869), host APK from `5fd7a8e0` with current native JNI payload from production-equivalent `1861d55e`; includes OS always-on/lockdown and legacy AWG transitions |
| Native Linux and Windows capture | **PASS**, [39772229380](https://github.com/StannisMod/amnezia-client/actions/runs/39772229380) and [39772229355](https://github.com/StannisMod/amnezia-client/actions/runs/39772229355); native production capture source is unchanged |
| Physical devices / signed iOS runtime | **NOT RUN**; see the acceptance boundaries below |

The Linux strict-firewall fix permits the reserved capture mark through the
legacy strict chain alongside the existing TUN and protected-socket exceptions.
The owned routing guard still blocks captured traffic between sessions.
The earlier diagnostic [39966881917](https://github.com/StannisMod/amnezia-client/actions/runs/39966881917)
intentionally tested an older Qt package with the current helper: its strict
probe failed, adding the capture-mark exception restored traffic, and the run
retained FAIL. It is causal negative evidence, not acceptance of that old package.
The new package passed without this diagnostic override. Its rescue report is
`CANCELLED_AFTER_ACCEPTANCE` with zero recovery operations. Across the 100-cycle
stress, the same service PID retained 15 handles and 12 threads; observed RSS
changed from 57.8 to 58.0 MB. Container results do not establish physical-host
network handover or hardware resource behavior.

The Darwin fixture now uses an explicitly configured loopback address. iOS CI
builds dependencies from source without the optional unavailable Conan mirror;
libagw now uses the same pinned Go 1.27.1 recipe as the other native components.
Upstream libagw race tests and its C/C++ archive smoke tests passed locally.
Local routing race tests, vet, workflow actionlint and script syntax checks also
passed. These do not replace the platform-specific acceptance results above.

The feature remains experimental and opt-in. Signed iOS runtime requires
matching app/extension provisioning and hardware. Android emulator acceptance
rebuilds the native JNI payload and records both source SHAs and APK checksums;
it does not claim to test an unmodified release APK. Android 9 lockdown-query
restrictions and physical-device policy behavior remain untested. Physical Android Wi-Fi/cellular
handover, sleep/wake, complete GUI interaction and unaffected protocol regression
acceptance remain separate work. The measured Linux data-path comparison below
shows overhead and does not establish cross-platform performance parity.
The public draft [PR #1](https://github.com/StannisMod/amnezia-client/pull/1)
collects the work for review. No merge or release has been performed.

---

## Continuation — 2026-10-22

Android emulator run `39771504529` at `ac06b611` passed traffic, native QUIC,
100 reconnects, resource checks, invalid-start recovery and legacy transitions.
It no longer crashed during policy changes, but remains **FAIL**: repeating a
routed start under lockdown timed out waiting for a rejection. The service now
rejects that policy before checking/launching VPN consent and explicitly emits
its unchanged disconnected state, so a repeated rejection does not depend on
StateFlow producing a duplicate value. New APK/emulator evidence is required.

Installed-service CI runs exceeded their configured budgets while the runner
was globally captured by a test VPN. Loss of the runner control plane is a
possible cause, not a proven product diagnosis. New disposable Linux runs arm
an independent local 420-second rescue before network changes. It uses existing
Qt strict-off, service deactivation/stop and owned-helper recovery operations;
it never flushes global network state. Triggered rescue records failure and
cannot turn acceptance green. A cancellation test verifies that a disarmed
watchdog executes no recovery operations. Reports include `.rescue.json`.

The Qt service also preserves the standardized resolver error-name category through IPC without exposing its error body; its compilation needs a fresh client build.

An independent x86_64 Android package lane uses the existing deploy script and
pins to supply a compatible emulator host without waiting for desktop runner
recovery. It is not a replacement for the full four-platform build gate.


### Latest observed gates

Shipping source was changed at `cd9d8305`; subsequent commits through `afd9375b`
change only disposable fixtures, test scripts, performance CI and documentation.
A path comparison confirms the client, deploy scripts and production routing
packages are unchanged since that source fix.

| Gate | Latest observed result |
| --- | --- |
| Linux native capture | **PASS** at `afd9375b`, [run 39772229380](https://github.com/StannisMod/amnezia-client/actions/runs/39772229380): full TCP/UDP/QUIC, IPv6, application scope, virtual uplink failover/outage recovery, 100 reconnects, pipe loss, hard crash, explicit recovery and exact native-state restoration |
| Windows native capture | **PASS** at shipping source `cd9d8305`, [run 39769773465](https://github.com/StannisMod/amnezia-client/actions/runs/39769773465) |
| Core race suite / cross-compilation | **PASS** in all three desktop test lanes and all eight architecture lanes of [39769773545](https://github.com/StannisMod/amnezia-client/actions/runs/39769773545) |
| Android APK compilation | **PASS**, all four ABI jobs of run `39769773545`, including current production Kotlin service changes |
| Android policy/emulator acceptance | **FAIL**, [39771504529](https://github.com/StannisMod/amnezia-client/actions/runs/39771504529); repeat-lockdown rejection fix requires a new compatible APK/emulator run |
| Installed Linux resolver stress | **NOT ACCEPTED**: [39769773506](https://github.com/StannisMod/amnezia-client/actions/runs/39769773506) cancelled with logs unavailable after exceeding its budget; new runs use independent local rescue |
| Full Windows / unsigned iOS clients | **IN PROGRESS** in run `39769773545`; prior build passes are historical evidence, not a completed new matrix |
| Linux comparative performance | **PASS** at `35e949c4`, [39771128512](https://github.com/StannisMod/amnezia-client/actions/runs/39771128512), with source SHA and binary checksums in the JSON report |
| iOS signed runtime / physical mobile devices | **BLOCKED / NOT RUN**: matching signing/provisioning and physical hardware still required |

The second performance run measured legacy/routed median throughput of
818.38/635.94 Mbit/s, CPU seconds/MiB of 0.01375/0.02375, and maximum observed
RSS of 12,164/46,464 KiB. Routed/legacy ratios were 0.777 throughput, 1.727 CPU
per MiB and 3.820 RSS. First verified transfer after starting the backend took
0.123/1.136 seconds. These are measurements on one disposable CI machine;
absolute rates vary between runs. No production performance parity is claimed.


At `ac06b611`, native Linux run `39771504567` completed traffic, native QUIC,
application scope, virtual uplink failover, outage fail-closed/recovery,
100 reconnects, pipe-loss/crash guards and explicit recovery. Its overall
result is still FAIL: the final exact route comparison found the fixture's
`203.0.113.0/24` route missing from table 222. Bringing eth0 down had removed
that route in the kernel; the simulated network manager now reapplies its own
static route on eth0 restoration, just as it already reapplies the default.
The final exact comparison is retained; this is not an exemption for route leaks.


Follow-up evidence: [performance run 39770515696](https://github.com/StannisMod/amnezia-client/actions/runs/39770515696)
PASS at `0232050c` (artifact `12421039401`). Median throughput: legacy
551.44 Mbit/s, routed 437.90 Mbit/s; routed/legacy throughput 0.794,
CPU seconds/MiB 1.647, observed RSS 4.005 (11,616 vs 46,524 KiB).
This is one 4-vCPU CI-host data-path comparison at MTU 1280, not cross-platform
parity. That report's source_sha was null because sudo stripped the environment;
workflow source SHA and binary checksums establish its provenance. `35e949c4`
passes source SHA explicitly and records time to the first verified transfer;
the old initialization timers end at different milestones and are not a valid
startup-latency comparison.

Linux run `39770515900` failed the new raw-AWG probe **before native capture**,
after ordinary TCP/UDP underlay observer probes passed. The peer received 12
outer datagrams and submitted 3 responses, but no inner flow reached it.
Run `39770943808` identified the cause: the client expected the fixture endpoint
`198.51.100.2`, but all observed AWG replies came from `10.0.2.2`. The client
correctly rejected the different endpoint. The disposable peer now explicitly
binds its outer socket to the off-link observer address; production endpoint
validation is unchanged. A local authenticated loopback-secondary-address test
passes with race detection. Keep the full Linux native gate FAIL until this
correction and the subsequent handover/crash/restoration scenarios pass.


Resumed at `1f56c109d9bc3596f2bba8ae75066408385ccb16`.
The latest source matrix [39624238843](https://github.com/StannisMod/amnezia-client/actions/runs/39624238843)
passed Android APK builds for all four ABIs, unsigned iOS app/extension,
Windows app/service/installers, desktop core tests and package cross-compiles.
Linux compiled, packaged and passed Qt tests, but its installed-service resolver
stress failed with `system resolver link configuration failed`. Therefore the
aggregate build gate is **FAIL**, not a green four-platform acceptance.

- Windows native acceptance: PASS, run `39624238817`.
- Linux native acceptance: FAIL, run `39624238708`, waiting for a helper event.
  The new diagnostics distinguish `ready` from `connected` timeouts and verify
  native observer reachability before capture. Underlay/handover acceptance
  remains open.
- Android emulator: FAIL, run `39624238657`. Traffic, 100 reconnects and the
  routed/legacy/routed transition passed, then a device-policy transition
  triggered a foreground-service `SecurityException`. The failure snapshot
  masked the instrumentation failure when the service process disappeared.
- Linux performance: FAIL, run `39624238994`; the baseline installer could not
  load `libxkbcommon-x11.so.0`, so no performance comparison was measured.

This continuation adds the missing installer runtime dependency, handles
foreground-promotion authorization loss without an uncaught exception,
restores emulator VPN consent after removing device-owner always-on policy,
and preserves the original instrumentation failure if resource collection
fails. Resolver initialization now bounds `NoSuchLink` retries across GetLink
and all setters; other D-Bus failures remain immediate and expose only their
error name, never their body. The exact cause of the earlier generic resolver
failure is still unproven; native CI must establish it.

Local Go 1.27.1 complete race suite (`-count=3`) PASS, including setter-race,
permanent-error, cancellation and error-redaction tests. Local native capture
is BLOCKED by forbidden netlink sockets and absent `/dev/net/tun`. The source
changes need new native/package/emulator CI evidence. No merge or release.

## Current verification — 2026-10-21

Resumed from `ff86843cbe35e7e8bc9fbcdec0d4a627cf425e57` on the existing
`feature/sing-box-routing` branch. Verified base:
`ddde43635e957ebf042d92787489da72d3394019` (`dev`).
Production fixes in this continuation: `e455c6a9`, `ff7016b9`, `ab782ce1`, `18efe265`.
No dev merge, server modification or release publication was performed.

The feature remains experimental and off by default. Source integration,
compilation, controlled native tests and physical-device acceptance are separate
claims. The four-platform handoff is **incomplete**.

| Check | Latest verified result |
| --- | --- |
| Android APKs | PASS at `18efe265`, [run 39583806899](https://github.com/StannisMod/amnezia-client/actions/runs/39583806899): all four ABIs, including JNI payload inspection |
| iOS unsigned app + extension | PASS at `ff7016b9`, run 39555388790. No signed IPA or device acceptance |
| Linux app/service/RUN + Qt regressions | PASS at `18efe265`, run 39583806899, and rebuilt/tested again at `395c491f` in [run 39584835912](https://github.com/StannisMod/amnezia-client/actions/runs/39584835912). All five settings/rule/application regression targets PASS |
| Windows app/service/EXE/MSI + Qt regressions | PASS at `ff7016b9`, run 39555388790. MSI log confirms installation success (exit 0). The subsequent installed-service step hung until the 120-minute job limit; EXE installed-service check was not reached |
| Installed Linux service | Five complete repetitions PASS with the unchanged `ff7016b9` installer in [run 39557237846](https://github.com/StannisMod/amnezia-client/actions/runs/39557237846): system resolver, strict switch, both app scopes, IPC reconnect, child crash recovery and exact OS-state restoration |
| Linux resolver stress | FAIL with the unchanged installer in [run 39558268939](https://github.com/StannisMod/amnezia-client/actions/runs/39558268939). A newly created TUN retained `~.` but lost its DNS server after reconnect; resolved reported no DNS scope and no route to host. The earlier isolated timeout is therefore not dismissed as an environment-only flake |
| Resolver correction | Source implemented at `ab782ce1`: D-Bus ownership/reconciliation of only the private TUN's DNS/domain/default-route state, change signals + periodic health checks, monitor shutdown before resolver rollback and fail-closed errors |
| Corrected Linux installed-package acceptance | PASS at `395c491f` in [run 39584835912](https://github.com/StannisMod/amnezia-client/actions/runs/39584835912): newly rebuilt RUN, clean installation, 20 resolver connect cycles, forced DNS-list reset recovery, cached FakeIP route identity, strict switch, both app scopes, IPC/crash recovery, exact OS-state restoration and package removal. Artifact: [routing-linux-verified-package](https://github.com/StannisMod/amnezia-client/actions/runs/39584835912/artifacts/12340530783). The earlier hybrid helper/service test at `ab782ce1` passed 100 cycles in run 39580790352 but was followed by an activation failure in another run; it is historical evidence, not the final stability gate |
| Windows installed MSI/EXE acceptance | PASS, including actual package uninstall, in [run 39584348717](https://github.com/StannisMod/amnezia-client/actions/runs/39584348717) and repeated PASS in [run 39584836050](https://github.com/StannisMod/amnezia-client/actions/runs/39584836050). Both reuse the verified `ff7016b9` installers. Reports cover DIRECT/VPN TCP/UDP, IPv6, system resolver, strict switch, both app scopes, IPC reconnect, child crash recovery and exact OS-state restoration. Earlier jobs failed at a separate SCM stop before uninstall; `60145bd9` exercises the package's own removal operations and asserts its service registration is gone. Overlapped raw pipe I/O fixes the acceptance client's deadlock |
| Core tests | Local Go 1.27.1 complete race suite and vet PASS after `18efe265`. Native Linux namespace acceptance PASS in [run 39583807024](https://github.com/StannisMod/amnezia-client/actions/runs/39583807024); native Windows acceptance PASS in [run 39583807047](https://github.com/StannisMod/amnezia-client/actions/runs/39583807047) |
| iOS device/runtime | NOT RUN; signed app/extension provisioning and a compatible device are required. Unsigned compilation is not device acceptance |

The `ab782ce1` matrix [run 39580790455](https://github.com/StannisMod/amnezia-client/actions/runs/39580790455)
confirmed Android APK builds (four ABIs) and Linux app/service/RUN. The later source
fix superseded that run before iOS/Windows completion; cancellation is not PASS.
The current full matrix is [run 39583806899](https://github.com/StannisMod/amnezia-client/actions/runs/39583806899).
Observe its actual result before marking the final source build gate PASS.
Focused helper/package tests do not replace final full-client builds.

An intermediate publication mistake at `df43f0b8` created an incomplete Git tree.
`ab782ce1` restores the full verified `61596aba` base tree and applies only the
intended eight changed/added files; comparison against `61596aba` has **zero
removed files**. Local source was retained, and no branch reset/force-push was
used. The failed diagnostic run at that incomplete intermediate commit never
reached resolver verification and is not acceptance evidence.

A further resolver stress repetition [run 39582872546](https://github.com/StannisMod/amnezia-client/actions/runs/39582872546)
failed during a later session activation after successfully recovering a forced DNS reset.
Do not treat the earlier 100-cycle PASS as proof of stable activation. `18efe265`
adds bounded startup waiting specifically for resolved's `NoSuchLink` while its
netlink event is still being processed; other bus/permission/configuration errors
remain immediate failures. Failure-event details are retained in test reports.
The freshly rebuilt `b099c757` RUN in [run 39583024531](https://github.com/StannisMod/amnezia-client/actions/runs/39583024531)
also failed a later activation after its 20 resolver cycles and app-scope probes.
Its successful compilation and Qt regressions are not package-runtime acceptance.
The startup-wait correction was added later at `18efe265`. The failed runs did not
retain the native error category, so `NoSuchLink` is a plausible startup race,
not a conclusively proven cause of those particular failures. The corrected
fresh package now passes the complete 20-cycle installed-service test. The
expanded five-by-20 diagnostic run [39585281916](https://github.com/StannisMod/amnezia-client/actions/runs/39585281916)
is still running at this checkpoint and is not marked PASS.
Full fresh Linux packaging is checked independently, including installation and
system-resolver stress; installer artifacts require a PASS report before acceptance.
Linux installer/test/removal commands are bounded, Python emits periodic stalled-thread
stacks, and focused native diagnostics retain only fixed allowlisted error categories;
raw syscall traces and fixture profiles/keys are never persisted as artifacts.

### Resumed desktop product fixes

- Linux exposes app split tunneling when the routed engine is enabled and
  provides an executable-file selector. Windows/Linux expose both app modes
  with that engine; legacy Windows retains its exclusion-only UI.
- Enabling domain routing no longer rejects desktop app scope or kill switch:
  the existing native/service integration implements those combinations.
- Restoring a routed Windows backup retains include mode. Linux restores the
  application mode/list/enabled state through the existing controller signals.
- UI models notify property bindings on repository-driven changes, including
  backup restoration, without double-emitting explicit setter notifications.
- A nonempty desktop app scope that requires the routed engine is rejected
  before starting an incompatible legacy transport; its saved rules are not
  silently ignored. Empty app lists retain existing all-app behavior.
- Regression tests exercise independent include/exclude lists, restored scope,
  live-editor notifications and rejection of unsupported legacy app scope.
  Linux and Windows CI run the settings/application UI regression targets.

Still unaccepted: physical mobile devices, signed iOS packet-flow/egress and
memory limits, native network handover, always-on/lockdown combinations,
performance measurements, complete protocol regression and full GUI interaction.
Keep these requirements open; successful builds do not close them.

Historical checkpoints below preserve the evidence and failures that led to
the current implementation; later entries supersede earlier source status.


## Historical implementation checkpoints

2026-10-19. Branch: `feature/sing-box-routing`.
Verified base: `ddde43635e957ebf042d92787489da72d3394019` (`origin/dev`).
The original DNS-fix checkout was left intact; this work uses a separate
worktree. All four submodules were initialized at the base's pinned commits.
No repository AGENTS.md was present.

**The four-platform handoff is not complete. No installable feature client has
been produced. Android now has opt-in Qt/service/JNI source integration and a compiled unified
native payload. Device validation and full client acceptance are still pending.**

## Implemented source

- Pinned, unified Go module: sing-box v1.14.3 plus AWG v3.1.20260814, Go 1.27.1,
  `with_gvisor`, committed checksums, no upstream source patches.
- Versioned shared rules, strict domain/wildcard validation, IDN/case/trailing
  dot handling, suffix boundaries, deterministic precedence, inverse routing,
  disabled rules and callable legacy site conversion without cached-IP rules.
- Dedicated AWG TCP/UDP outbound and a mandatory native protected-socket
  contract; a separate protected DIRECT outbound; no fallback from VPN to DIRECT.
- Session compiler for one capture inbound, DNS hijacking, managed FakeIP,
  explicit DNS resolver detours, AWG parameters and disabled default logs.
- Native route installation is deliberately not attempted by this core.
- Four-platform client-baseline CI lanes using existing deploy entry points;
  Android uses hosted runners and all four ABIs. iOS has an opt-in unsigned
  compile path. Aggregation fails if a required lane fails/cancels/skips.
- Build reports distinguish baseline compilation, native feature integration,
  signing, installers and runtime tests. No automatic release publishing.

Architecture, source pins, runtime caveats and alternatives are in ADR-001.md.

## Executed verification

Go commands ran from `native/routing` with Go 1.27.1 on Linux x86_64.

| Check | Status | Evidence / limits |
| --- | --- | --- |
| `go mod verify` | PASS | All module checksums verified |
| `go vet -tags with_gvisor ./...` | PASS | Static Go checks |
| `go test -mod=readonly -tags with_gvisor -race -count=3 ./...` | PASS | AWG, engine and rule packages; three repetitions; no race findings |
| AWG inner IPv4 and IPv6 | PASS | Real local TCP and UDP echoes through encrypted AWG peers, non-default J/S/H parameters |
| Two domains sharing one real IP | PASS, host flow test | Real sing-box FakeIP and routed connections reach different observers; test DIRECT factory maps observer to loopback |
| Remote AWG loss | PASS, host flow test | Fresh VPN-selected flow fails; DIRECT observer sees no additional connection |
| Managed DNS | PASS, host flow test | Actual local UDP DNS server; A/CNAME and AAAA responses; caching and explicit clear; captured A query gets FakeIP without reaching upstream |
| Rules/migration | PASS | Wildcard/apex boundaries, normalized duplicate conflicts, longest suffix/prefix, IDN, inverse mode, disabled-rule persistence, cached-IP omission |
| Android arm64 Go packages | PASS | `GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...` |
| Android armv7/386/amd64 Go packages | PASS | Same command with corresponding GOARCH and GOARM=7 for arm |
| iOS arm64 Go packages | PASS | `GOOS=ios GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...`; **no c-archive/framework or extension linking** |
| Windows amd64 Go packages | PASS | Same command for GOOS=windows; **no DLL/service linking** |
| macOS arm64 Go packages | PASS | `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor ./...`; core package regression only |
| CI source lint | PASS | actionlint 1.7.7; YAML parsed; deployment shell passes `bash -n` |
| Manifest smoke check | PASS | Compile PASS does not imply runtime PASS; iOS signing stays BLOCKED |

The local host has no `/dev/net/tun` and forbids netlink sockets. The engine
flow tests supply a test-only loopback interface inventory. They do not test
physical/Internet egress, native capture, policy routes or interface monitoring.
The initial real-engine startup reproduced the netlink restriction; tests were
then explicitly scoped to flow routing, rather than marked native PASS.

## Full-client baseline attempts

| Platform | Command / host | Status | Blocker |
| --- | --- | --- | --- |
| Linux installer | `deploy/build.sh --generator Ninja --installer all` | BLOCKED | Existing Qt 6.10.1 available, but Qt Installer Framework absent |
| Linux app/service compile | `deploy/build.sh --generator Ninja` with separate build directory | BLOCKED | Conan 2.28.0 cannot resolve `go/1.23.12` required by libagw/1.0.8; configured Amnezia Artifactory remote is rejected as an invalid Conan remote |
| Android ARM64 APK | `deploy/build.sh -t android --abi arm64-v8a --apk` | BLOCKED | Qt Android toolchain, Android SDK/NDK absent; script fails on missing Qt Android toolchain file |
| iOS app + extension | `deploy/build.sh -t ios` | BLOCKED | Linux host has no Xcode generator, Apple SDK or Qt iOS; signing identities and app/extension profiles also unavailable |
| Windows app + service + installers | `deploy/build.bat --installer all` | NOT RUN | No Windows host, MSVC, WiX or Windows Qt in the executor |

CI baseline lanes are source-added and linted, not evidence of executed remote
builds. CI must be observed at the pushed commit. Existing Android-only self-hosted
runner availability was not established; the new lanes do not require it.
No APK, IPA, RUN, EXE or MSI from this feature was generated. Old DNS-fix
installers found elsewhere were not reused or presented as feature artifacts.

## Functional acceptance by platform

| Requirement | Android | iOS | Linux | Windows |
| --- | --- | --- | --- | --- |
| Native capture/TUN integration | SOURCE INTEGRATED; FD test PASS | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Native DIRECT/protection and AWG bootstrap | SOURCE INTEGRATED; device NOT RUN | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| DNS/FakeIP under OS capture | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Qt persisted rule editor/profile migration installed | SOURCE INTEGRATED; client build pending | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Reconnect, crash, shutdown, native fail-closed | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Per-app rules and conflict precedence | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Installer/device/extension smoke test | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Existing protocol regression | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

## Remaining engineering and external assets

Android integration now overlays the routing bridge into the existing AWG
Go payload, preserving old JNI entry points. ARM64 c-shared compilation with
NDK 27.0.12077973 passed; exported old/routed JNI and 16 KB ELF alignment were
checked. The same native FD adapter passed raw DNS/FakeIP and failed-start/
shutdown cleanup tests with race detection. Qt migration contract tests passed.
The next gate is the complete APK compile, payload inspection and device test.

The actual service-process runtime/load behavior still requires device proof. The existing AWG Go dependency
is linked through CMake; blindly adding another Go shared library is not valid.
Then replace the AWG packet reader only for the experimental routed session,
wire persisted rules from Qt, and run a real ARM64 APK against a controlled AWG
endpoint. Retain old backends for unaffected sessions/protocols.

iOS must reconcile the new module with the existing AWG/XRay Go payload and
connect the same engine to the existing Network Extension packet flow. Linux
and Windows need their existing service/TUN/driver/DNS lifecycle integration.
None of these is completed by the package-only cross-compiles.

External prerequisites for complete verification: working source/prebuilt Conan
dependency access; Android toolchains and device/emulator; Windows build/test
runner; macOS/Xcode runner and Apple device. Signed iOS installation additionally
requires matching app and extension identities, provisioning and entitlements.
A controlled unchanged AWG server and two independent egress observers are
needed for actual network-path acceptance. Do not put credentials in logs or
committed fixtures.

Other open work: endpoint roaming/bind refresh, native network handover,
lockdown/always-on policy, loopback/LAN/resolver regression, DNS TTL expiry and
reconnect restoration, QUIC, DoH/DoT fallback, CNAME edge cases, 100-cycle
resource checks, performance/memory measurements and complete distributable
license notices. Keep feature activation unavailable until host integration is
implemented and verified. No server or dev-branch changes were made.

## Android implementation details in this checkpoint

- `Awg.startVpn` selects the routed path only when `sing_box_routing` is present.
  It retains the legacy AWG/WG JNI functions and does not retry them after a
  routed-start failure. One app VpnService builder supplies the capture FD.
- The Go host owns that FD, refuses a second reader and always releases it and
  its JNI global callback on a failed start or normal stop. Native socket
  callbacks use `VpnService.protect` before connect/send; counters and handshake
  status are returned without exposing the private UAPI.
- Qt adds a persisted, default-off experimental AWG switch on Android. Existing
  site lists/modes serialize as schema v1 names, without cached DNS IPs. New
  routed domain entries do not perform `QHostInfo` startup resolution.
- The capture includes IPv4 and all IPv6, including the FakeIP ULA range.
  An AWG profile with no IPv6 path cannot fall back to DIRECT for VPN flows.
- Conan pins AWG Android source commit 5c16489e2cd9ed3a0a7a27c7445bba5238132f86,
  adds the core to the same `libwg-go.so`, and uses a Go-1.27.1-specific checked
  CLOCK_BOOTTIME patch to retain suspend-aware mobile timers.
- Full Kotlin/client/payload CI verification has been added. Full client builds
  at the preceding core-only commit passed for Linux and all four Android ABIs;
  those older APKs do not contain the new Android integration.


## Update: native mobile integration and editable rules (2026-10-19)

This update supersedes the earlier source/CI statements above where they differ.
The four-platform mission remains incomplete. No native VPN device acceptance
has been executed, and desktop routing integration remains open.

- Android: actual Kotlin protocol modules and unified JNI payload compiled on
  all four ABI CI lanes at `fe9a5a8a`. Full APK packaging reached the modified
  Conan recipe and exposed a dangling-symlink copy failure. The recipe now
  preserves symlinks; the corrected APK build still needs to pass.
- iOS: CI run 39253601451 built the arm64 AWG/XRay/routing c-archive, verified
  old/new C symbols and typechecked the Swift public PacketTunnelFlow adapter.
  The complete unsigned app/extension build was still running when recorded.
  This is compilation evidence, not entitlement/device/underlay proof.
- The iOS implementation uses public readPackets/writePackets, one packet
  reader and the existing Go archive. Network changes replace the Go session
  while retaining that reader and OS capture. includeAllNetworks is rejected;
  provider-owned BSD sockets require native egress verification on a device.
- The new Qt editor persists per-rule domain/suffix/CIDR, DIRECT/VPN and
  enabled/disabled state plus the default route. First activation migrates the
  active legacy list without resolved IPs. Existing settings backups include
  the new Conf keys. Legacy lists and other protocols are retained.
- Both mobile hosts now choose a private persistent FakeIP database. Only
  domain/FakeIP identities persist; real DNS response caches are fresh on a
  transport restart. File permissions are restricted to the application user.
- Local tests passed: real gVisor packet-FD and public packet-flow managed DNS;
  three restart cycles preserving IPv4/IPv6 FakeIP identity without address
  reassignment; C ABI failed start, packet DNS/FakeIP, restart, stats and stop
  lifetime; Go race tests; Qt canonical-rule migration/validation contract.
  QML parsing passed. Full Qt controller persistence/backup tests are added
  to the existing UI regression target and need CI execution.

Open acceptance remains: complete feature APK and unsigned iOS app builds,
Android emulator/device and iOS device network-path verification, stable native
network handover/100-cycle cleanup, performance, all protocol regressions,
Linux/Windows service capture and native DIRECT integration, installable desktop
artifacts containing routing, and signed iOS distribution. Ordinary host builds
or pre-feature installers must not be reported as feature acceptance.

## Actual APK acceptance and UDP regression (2026-10-19)

The complete build run `39255117799` at `34ce45ea` passed all four Android
ABIs, unsigned iOS app/extension, Linux and Windows build lanes, and existing
Qt persistence/UI tests. Those results supersede earlier pending build entries.
Desktop artifacts from this run still use the legacy routing backend.

An actual packaged x86_64 APK now runs under its production `AwgService` in a
disposable Android 35 emulator. Run `39294909757` verified FakeIP DNS, DIRECT
TCP/UDP and AWG TCP against independent host/netstack observers sharing one
real IP. AWG UDP **FAILED**. No Android acceptance pass is claimed.

The failure reproduced in a new host test exercising sing-box's UDP router,
which the earlier connected-UDP transport test did not cover. Binding an
unconnected AWG UDP flow to the configured tunnel address, rather than an
explicit wildcard address, fixes the pinned userspace stack's `no route to
host` error. Both IPv4/IPv6 unconnected UDP and the FakeIP UDP routing
regression pass locally with race detection. A newly linked APK must still
pass the emulator matrix before this is marked fixed on Android.

The emulator workflow uses a test-only instrumentation APK and temporary
signing identity. It re-signs a disposable copy of the feature APK and verifies
that every native payload byte is preserved; release artifacts are untouched.
Private fixture keys and fixture-bearing test APKs are never uploaded.

## Linux service integration checkpoint (native runtime verification pending)

- The persisted experimental editor and routing profile now reach the existing
  desktop service IPC on Linux. The service launches and owns a private Go
  child, packaged beside it through CMake and built from the pinned module.
  Credentials cross stdin, not command lines or configuration files.
- The child owns one TUN and gVisor reader. A dedicated capture table and one
  inverse-mark rule per family capture ordinary flows after the local table.
  Protected DIRECT/AWG sockets skip only this capture rule and continue through
  native OS policy; no default gateway is forced. Occupied reserved state or
  overlapping mark policies cause startup rejection, never replacement.
- Startup, shutdown and partial-start rollback track exact owned routes/rules.
  A helper crash leaves a lower-priority blackhole until explicit recovery by
  the service. Recovery recognizes exact owned entries and refuses foreign
  policy state; it never flushes a shared table.
- systemd-resolved receives DNS on the new VPN link and is reverted on stop.
  The local `127.0.0.53` stub is never routed to a router. If selected as the
  engine resolver, its numeric upstream is snapshotted before VPN DNS changes.
- Per-app desktop routing and the existing OS/strict kill switch are explicitly
  gated rather than silently bypassed. Their integration is still unfinished.
- Local checks: native helper compilation; AWG profile/parameter conversion and
  rejection tests with race detection; Go vet; Qt domain contract; syntax check
  of the new C++ child owner; workflow/Python checks. These are not native VPN
  acceptance. A real network-namespace CI checks capture, independent TCP/UDP
  observers, native policy routing, IPv6, CNAME, loopback, AWG/helper loss,
  inverse mode, FakeIP persistence, 100 reconnects and exact route restoration.
  Installed Qt-service, systemd-resolved, installer and network handover tests
  remain separate requirements.

The test-only peer is excluded from Android/iOS package cross-compilation;
otherwise `go build ./...` would try linking an unrelated host executable with
CGO disabled. Android CI retries transient failures downloading the same pinned
NDK version; it does not substitute a different NDK or payload.

Runtime follow-up: the first Linux namespace run (`39297636360`) caught a
startup route-encoding error: the netlink API requires an explicit default
destination even when its family is supplied. That source correction is
pending a rerun; no Linux native PASS is claimed.

The emulator lane now builds the current unified JNI payload with the same
reproducible script as the full-client lane. It can apply that payload to the
packaged test APK only after checking its production Android host sources are
unchanged from that APK's source SHA. The report identifies both SHAs and the
native checksum. This incremental APK is emulator-only evidence, not a newly
compiled Qt client, installer, release artifact or physical-device acceptance.

## Windows source integration and mobile runtime follow-up

The desktop service owner now has a platform-neutral name and is wired into
the existing Windows service IPC as well as Linux. The Windows helper uses the
repository's pinned Wintun 0.14.1 dependency and the same routing/AWG module.
It chooses each destination's native route via GetBestRoute2 across native
interfaces, compares prefix length plus route/interface metrics, excludes the
capture adapter, and applies IP_UNICAST_IF/IPV6_UNICAST_IF before TCP connect
or each UDP send. UDP syscall fast paths are deliberately hidden so that they
cannot bypass that protection. Loopback retains its native local path.

The helper owns adapter DNS/addresses/routes and a dynamic WFP DNS guard;
specific native routes receive more-specific capture routes so literal VPN
destinations cannot escape merely through a pre-existing LAN route. The cache
directory has an explicit SYSTEM/Administrators ACL and an exclusive file
lock. Existing per-app routing and OS kill-switch combinations remain gated.
Windows helper-crash fail-closed policy, installed-service/installer smoke,
handover and real-device behavior are still unfinished. Source integration
and a successful Go cross-build do not establish Windows runtime acceptance.

A dedicated Windows CI now exercises the actual route API/ABI, Wintun capture,
system DNS, DIRECT/AWG TCP/UDP observers, IPv6, loopback, inverse policy and
100 reconnects with native route/DNS restoration. Results are pending.

Android incremental run `39298167660` confirms the UDP correction under the
actual APK's AwgService: shared-IP domain separation, TCP/UDP on both paths,
suffix/exact precedence, CNAME, IPv6 TCP/UDP, system resolver and loopback all
passed. A later inverse-mode check after peer/session restart timed out, so
the full Android result remains **FAIL**. Fresh host tests now cover both
default policies and pass; reconnect/peer recovery remains under investigation.


## 2026-10-20: full builds passed; first-packet race reproduced and corrected

Full CI run `39301511270`, source `6767d516`, passed all four Android ABI APKs,
unsigned iOS application/extension, Linux installer, Windows EXE/MSI, and core
race tests on Linux, Windows and macOS. This confirms desktop service packaging
and compilation; it does not establish native runtime acceptance.

Native runs `39301511519` (Linux), `39301511380` (Windows), and `39300503667`
(Android) still failed. A local regression using real UDP DNS through AWG,
rather than a hosts-only DNS backend, reproduced the shared startup failure.
AWG snapshots S4 before entering its first blocking TUN read; applying UAPI
after device construction could leave that read using the old padding offset.
The first data packet was then rejected as an unknown message. Parallel A/AAAA
queries and peer/session restarts made the packet loss visible.

The shared flow-device constructor now suppresses eager EventUp and completes
that initial read without consuming a packet after UAPI application. Its next
iteration reloads the configured padding before traffic starts. The disposable
peer uses the same constructor. First-flight DNS burst and real upstream DNS /
DIRECT / AWG restart regressions pass repeatedly; the complete local Go race
suite passes. Native reruns remain required before upgrading any acceptance
status. The Android lane now uses the latest successful full APK as its host.

Linux capture also matches a clear socket-exemption bit directly. Inverting a
rule would invert its entire selector, including iif lo, and could capture
native input lookups. Explicit recovery recognizes both the new owned rule and
the previous owned form. The actual namespace test remains the deciding check.

Native Linux run `39371691161` progressed through real TUN TCP/UDP, IPv6,
CNAME, native policy routing, loopback, AWG outage, inverse mode, FakeIP
persistence and 100 reconnects after the startup fix. It then failed explicit
recovery after the forced helper crash. The pinned netlink decoder restores
Mark/Mask but never MarkSet; recovery must identify the exact owned mask/value
instead of relying on that flag, and explicitly encode MarkSet on deletion.
The same correction makes preflight detect foreign mark policies. A new native
conflict-rejection scenario verifies those rules remain untouched. The entire
Linux acceptance result remains FAIL until recovery/restoration also passes.

## Native follow-up: Windows pass and Android resource cleanup

Windows native run `39371691099` at `afa7f399` **PASSED** actual Wintun capture,
independent DIRECT/AWG TCP/UDP, IPv6, managed/system DNS, CNAME/suffix rules,
loopback, AWG outage without DIRECT fallback, inverse mode, persisted FakeIP,
100 reconnects, and exact native route/DNS restoration. This is disposable-host
helper acceptance; installed Qt service, installer smoke, handover, helper-crash
policy and the gated OS kill-switch/per-app combinations remain unverified.

Android run `39371691061` passed all traffic scenarios and 100 reconnects,
including inverse mode and persisted FakeIP, but the complete result **FAILED**.
The expected failed-start test had an IPC ordering race: DISCONNECTED precedes
ERROR, so the test must consume both before starting the replacement session.
It also measured descriptor growth from 95 to 196 in the same service process
(threads 31 to 34, RSS 154724 to 165324 KiB). A new local repeated-capture test
reproduced one leaked eventfd per reconnect in the pinned gVisor fdbased endpoint.

Descriptor capture now uses the existing packet-flow channel endpoint with a
single Go pollable-file reader and nonblocking native writes. It closes that
reader and the capture descriptor explicitly, avoids dependency-internal access
or patches, and passes the local eventfd regression and complete Go race suite.
Native emulator resource verification and throughput measurements remain
required; packet-copy overhead must not be inferred from compilation success.

Linux run `39372104523` again completed traffic and 100 reconnects. Recovery
removed its rules, then failed deleting dumped default blackhole routes because
the pinned encoder also requires an explicit destination for deletion. Recovery
now restores the correct family-specific /0 destination before deleting the
exact owned route. The next native run must prove complete restoration.

## Android preflight and final native-test refinements

Android run `39372709101` at `1cdf51cf` confirmed the descriptor fix: **93 -> 93**
in the same service PID over 100 reconnects (threads 28 -> 34, RSS 155008 ->
167040 KiB). Traffic, inverse mode and FakeIP persistence passed again. The
complete result remains **FAIL**: DNS timed out on the valid connection after
an intentionally invalid profile. Unsupported routing schema was still being
rejected only after Builder.establish had created a transient Android VPN.

The host now calls shared native schema/routing validation before establishing
or replacing the OS interface; Start repeats the same validation defensively.
The new JNI method is part of the existing unified Go library. Tests verify
preflight rejects unsupported rules without creating capture/cache resources.
Because production Kotlin changed, emulator CI now waits for this exact
source commit's successful full-client build instead of applying JNI to an
incompatible older APK. Failure diagnostics snapshot live routing before test
cleanup disconnects the VPN. Native recovery verification is still pending.

Linux run `39372709136` completed explicit recovery and removed owned capture
rules/blackholes, then failed its final native-route text comparison. The test
now waits for native IPv6 DAD/link-local initialization before taking the
baseline, records that baseline, and prints a precise restoration diff. Native
route restoration is not marked PASS until the revised run completes.

A real QUIC/TLS host test now transfers a segmented stream through AWG at MTU
1280, verifies its digest and covers inner IPv4 and IPv6. It passes locally
with race detection using the already-pinned QUIC dependency. This is flow
transport evidence; native application/TUN QUIC acceptance remains unrun.


## Owned AWG flow-stack shutdown and portable fixture binding

Linux native run `39373901624` at `2a46d327` **PASSED** the complete namespace
suite, including foreign-mark conflict rejection, traffic, IPv6, 100 reconnects,
helper-crash fail-closed behavior, explicit recovery, and exact native state
restoration after a settled IPv6 baseline.

The repeated full-core CI then exposed a close/send race in the pinned AWG
convenience netstack: it closed incomingPacket while a gVisor notifier could
still send a delayed TCP packet. The routing module now owns its small private
flow-TUN adapter using the same pinned public gVisor protocol/socket APIs. It
cancels producers, waits for admitted I/O, stops the stack and releases queued
views without closing a channel under a sender. AWG device/crypto code and its
wire protocol are unchanged; no dependency patch or second runtime is added.
An adversarial pending-output shutdown test and repeated TCP/UDP close tests
pass with race detection, as does the complete suite with CI's count=3.

The Windows core runner also rejected the fixture's fixed outer UDP port
51820 as reserved by the host. The disposable peer now binds an available
system-selected port, records it in its private generated profile, and retains
it across restart. Fixed inner observer ports remain inside the userspace AWG
stack. Native acceptance must rerun because the owned flow adapter changed.


## Native acceptance passed on the owned flow stack

At source `f7847c02`, Linux run `39375044711` and Windows run `39375044707`
report native_capture=PASS, reconnect_cycles=100 and os_state_restored=true.
Linux also proves the helper-crash blackhole and explicit recovery. These are
helper tests on disposable hosts; the Linux namespace deliberately uses
--no-system-dns and does not establish installed-service/systemd-resolved
acceptance. Windows installed Qt-service, installer smoke and helper-crash
fail-closed policy remain outside that pass.

Android run `39376118150` at CI-only source `d75d1850` **PASSED**. It used the
full x86_64 APK host built from `f7847c02`, with identical production Android
host sources and a freshly linked unified JNI payload. Both SHAs/checksums are
in its artifact. It verifies shared-IP domain identity, DIRECT/AWG TCP/UDP,
suffix/exact precedence, CNAME, inner IPv6, system DNS, loopback, AWG outage,
inverse mode, persisted FakeIP, 100 reconnects, and invalid-profile preflight
rejection followed by a successful valid start. The preflight case does not
claim every possible post-establish native-failure path was tested.

The same service PID (3624) stayed alive throughout: descriptors **93 -> 93**,
eventfds **5 -> 5**, and capture descriptors **0 -> 0** at disconnected
checkpoints. Threads were 31 -> 35; RSS was 157648 -> 168520 KiB. RSS is a
measurement, not a leak/performance acceptance threshold. Physical devices,
handover, always-on/lockdown and native application QUIC remain unrun.

The compatible APK job can pass before other platform jobs finish. Emulator CI
verifies that specific job, source SHA and host compatibility; the separate
full build gate still requires every platform. CI-only follow-ups leave the
in-progress full source build running.

Native acceptance reports/artifacts:

- [Linux run 39375044711](https://github.com/StannisMod/amnezia-client/actions/runs/39375044711), artifact `12243097357`.
- [Windows run 39375044707](https://github.com/StannisMod/amnezia-client/actions/runs/39375044707), artifact `12243108193`.
- [Android run 39376118150](https://github.com/StannisMod/amnezia-client/actions/runs/39376118150), artifact `12242654376`.

No dev merge, release publication or production-server change was performed.

## Final source build verification

[Full source matrix 39375044626](https://github.com/StannisMod/amnezia-client/actions/runs/39375044626)
completed successfully at `f7847c02895d5c3e356811b7d0d03e3927f42eeb`.
All four Android ABI APK jobs, Linux application/service/installer, Windows
application/service/EXE/MSI installers, unsigned iOS application/PacketTunnel
extension, three desktop race-test jobs (count=3), eight package cross-compiles
and the aggregate build gate passed. Windows artifact: `12245266425`; unsigned
iOS artifact: `12244427896`; Linux artifact: `12243950123`.

Later commits only adjust CI/reporting; shipping source remains the verified
`f7847c02` source. Android native acceptance uses the compatible full APK host
from that same matrix. A build PASS is not installed-client acceptance, signed
iOS device acceptance or release approval. The feature remains experimental
and off by default, with the limitations listed at the top of this report.

## Windows helper-crash guard — pending native acceptance

The private helper now installs a separate non-dynamic WFP sublayer before
capture. Its default outbound IPv4/IPv6 block survives helper termination;
only the helper executable, captured interface LUID, native loopback and DHCP
are permitted. Graceful shutdown removes the exact owned filters after closing
the engine. An unclean session refuses restart until explicit recovery removes
its private keys, transactionally, without flushing other firewall policies.
This protection lasts until explicit recovery or BFE restart; it is not a
boot-time filter and does not yet integrate the existing strict kill switch.

The Windows native suite now forcibly kills the helper, checks that Wintun is
gone while native outbound TCP connect is denied by WFP (WSAEACCES), rejects a stale
restart without losing protection, recovers, and reconnects. This new suite
must pass before helper-crash protection is marked accepted.

## Desktop application scope — pending native acceptance

Desktop profiles now translate application include/exclude lists into process
path rules before destination rules, with anchored literal-path matching and
case-insensitive Windows identity. Linux symlinks are normalized to the kernel
executable path when present. Shared DNS is captured first; unidentifiable
non-DNS process owners are rejected. A process selected for VPN still follows
its domain DIRECT/VPN rules; an app outside the selected scope uses DIRECT.
Mobile application scope remains owned by its native platform service.

Actual pinned sing-box parser/matcher tests cover include/exclude precedence,
unknown owner rejection, DNS capture, path metacharacters and Windows casing.
The local complete race suite passes count=3. Linux and Windows native suites
now compare separate Python/Go executables against the same FakeIP destination
for both TCP and UDP. Those new native cases have not passed yet.

Windows run `39395467839` passed traffic and 100 reconnects, then failed the
first crash assertion. Unconnected UDP sendto may return before WFP drops a
packet, so that API return value is not packet-delivery evidence. The revised
suite verifies surviving WFP objects directly and checks synchronous TCP
connect denial, with native reachability checks before capture/after recovery.
No crash protection PASS is claimed from the failed run.

A later reporting-only matrix `39380227075` exposed a macOS fixture timeout
in TestEngineRealDNSAndPeerRestart. The prior verified source matrix remains
historical evidence; repeatability on macOS is still under investigation.

## Strict-switch service integration and installed-package acceptance — pending

The Qt service now owns narrow firewall exceptions for the protected routing
helper and the captured interface. Windows uses a separate owned filter group,
IPv4/IPv6 app identity and capture LUID; Linux validates and owns a two-rule
iptables/ip6tables chain for its reserved socket mark and capture interface.
The existing strict policy remains blocked between sessions; live toggles
reapply the owned exceptions. Cleanup restores the strict state before the
native child releases capture. Domain DIRECT rules and application scope are
still evaluated by the shared engine, rather than legacy IP-filter rules.

Unexpected service-pipe EOF, signals and runtime statistics failure now close
the engine but retain native fail-closed policy. Explicit stop/recovery releases
that owned policy. Both native suites check pipe-loss recovery as well as hard
termination. This guard is not boot/BFE-restart protection.

The first application-scope native runs rejected unknown owners. Desktop hosts
with no Go network monitor had not seeded sing-box's interface inventory, and
newly captured source addresses were absent from that pre-TUN snapshot. The
host now initializes its native inventory and reports its assigned capture
addresses through the platform API. Unknown ownership remains rejected.

Full CI now builds a small client of the real QtRO switch API, installs the
Linux RUN package and both Windows MSI/EXE packages, then tests the installed
service's actual child, system resolver (including systemd-resolved), live
strict-switch changes, application scope, IPC reconnect, helper crash/recovery
and OS-state restoration. These are new tests, not yet PASS evidence.

Local Go race suites pass count=3; the DNS/restart regression passes count=30.
The real QtRO probe compiles/links, and the edited Linux C++ service/firewall
units pass syntax checking. Native Windows ABI/guard-lifetime checks passed in
run 39396896294 before that run stopped at the application-scope rejection.
Correctness TCP deadlines now allow the existing AWG/TCP retry timers on loaded
CI hosts; the independent first-flight A/AAAA UDP burst still has a 2s deadline.


## Native application scope and crash acceptance passed; QUIC probes added

At `6d111d66`, Linux `39449842500`, Windows `39449842545` and Android
`39449842506` passed their complete native suites. The desktop suites include
separate executable owners, include/exclude TCP/UDP, retained protection after
service-pipe loss and forced helper termination, explicit recovery, 100
reconnects and native-state restoration. Windows additionally checks native
WFP ABI/object lifetime and TCP WSAEACCES after termination. Installed Qt service
and strict-switch acceptance remain pending in full matrix `39449842520`.

The new disposable `traffic-probe` verifies TLS 1.3 against an ephemeral fixture
certificate and a 64 KiB stream digest using ordinary native UDP sockets.
Linux/Windows namespace/Wintun and Android actual-service suites now request
DIRECT IPv4 and VPN IPv4/IPv6 QUIC probes. Android packages the probe executable
in the throwaway instrumentation APK and executes it in a separate process
with the instrumented app UID; the production APK and its single Go runtime
are unchanged. Local race tests verify both observer labels and rejection of
a different CA. Native QUIC results are still pending and are not claimed PASS.
