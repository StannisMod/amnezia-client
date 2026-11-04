# Controlled AWG 3 header protection

This action follows the compatible userspace AWG 2-to-3 software update. It enables
**HeaderProtectionKey** and the padding required for it, without reinstalling the
VPN, replacing any peer, or generating a new WireGuard identity. Other AWG 3 options
remain unchanged. Kernel AWG and the legacy `amnezia-awg` container are unsupported.

## Prepare existing users

1. Upgrade the VPN software with **Update protocol**, keeping old profiles working.
2. Run **Set up connection updates** to install/upgrade the delivery service. Its
   HTTPS certificate, signing key, issued tokens and counters survive this upgrade.
   A failed service upgrade restores the previous immutable container. The service
   remains independent of the VPN on TCP 8443; provider firewall access is required.
3. For each existing peer, open its user sheet and choose **Share connection
   updates**. This issues a token for the live peer's existing public key. It does
   not create a peer, private key, address or new VPN profile.
4. The recipient imports this invitation into the compatible app which already
   holds the original self-hosted AmneziaVPN app (`.vpn`) profile. Exactly one matching client identity and server
   public key are required. The app attaches update metadata to that profile;
   keys, addresses, DNS, names, local routing and default selection are preserved.
   Reimporting the same invitation preserves accepted revision/anti-replay state.
5. Each recipient refreshes the connection in the app. After authenticating and
   saving the signed settings, the app acknowledges its current configuration and
   AWG 3 capability using its existing device key. No device private key is sent.
   Opening a new connection also performs this exchange. Refresh/ack share the
   existing ten-second total deadline; an acknowledgement failure does not discard
   a valid updated profile or stop an ordinary cached connection.

An update invitation contains a confidential bearer token, but no VPN private
key. It cannot add a new VPN connection by itself. Users should accept invitations
only from the server owner they trust. A copied VPN identity still represents one
peer; issue distinct identities per device if they must be managed independently.

## Enable protection

Disconnect the administrator's local VPN, then choose **Enable AWG 3 header
protection** on the protocol page. The confirmation explains the interruption and
client requirements. All non-administrator live peers must have an active token
and a recent valid readiness receipt for their current public settings. An issued
but unimported invitation, a bare token without the device key, an older app,
expired readiness or a revoked token does not pass this gate. The current cached
administrator identity is updated locally after the SSH operation succeeds.

The existing VPN container briefly restarts. Recipients reconnect **from the app**
to fetch the signed protected configuration. Existing tunnels and OS-only
reconnects using old cached parameters must be restarted in the app. The readiness
check establishes receipt, key possession and advertised capability; it cannot
attest that an owner will keep the same app installed or refrain from changing
local configuration later.

## Transaction and recovery

The host-side orchestrator is extracted from the running, owned delivery-service
image and invoked over SSH with a private request file. The serving container
never receives the host Docker socket. The orchestrator:

- Takes the existing `amnezia-awg2` maintenance lock; rejects stopped, kernel,
  old-daemon, custom-mount/network/port layouts and unsaved runtime changes.
- Pins the original container ID and delivery image ID, verifies the pinned
  delivery identity, and snapshots saved/live configuration in a root-only audit
  directory under `/var/lib/amnezia/updates/awg3-protection-<id>`.
- Generates one random shared header-protection key. S1-S4 are raised to at least
  the required 12-byte nonce size; packet-size collisions are avoided. Server
  identity, endpoint, PSKs, peer associations, addresses and startup script remain.
- Writes the persistent candidate, restarts the **same** VPN container, and
  compares the actual effective configuration with exactly the intended change.
  Only known explicit-zero defaults, off flags and roaming peer endpoints are
  normalized; identities and peer AllowedIPs/PSKs remain strict.
- Publishes the new public parameters atomically to active subscriptions, using
  a state tag to reject an intervening token/publication change.

Failure restores the original saved configuration, restarts the original daemon
and verifies the old effective configuration. If publication may have happened,
old settings are republished at a **new, higher revision**. Restoring a lower
counter/state snapshot would strand clients which already accepted the new version
and is never used as rollback. Outcomes distinguish rejected, rolled back,
rollback failed and missing/unknown SSH result. Logs contain safe phase names;
configuration/audit files remain private. A retry of an already protected server
keeps its active key and synchronizes the admin profile without another VPN restart.

This does not add a crash/power-loss/SIGKILL recovery supervisor. Preserve the
remote audit files for manual recovery after those events. Do not change peers or
protocol settings concurrently from another administrator. Deferred local token
revocations are flushed before the operation; separate administrators do not share
that local outbox.

## Readiness exchange

The HTTPS payload optionally includes a signed ephemeral X25519 `ackChallenge`.
A compatible app verifies the envelope and configuration binding, derives a shared
secret from that challenge and its original X25519 device key, then sends
`POST <subscription-url>/ack` with the original envelope, capability and proof:

```
HMAC-SHA256(X25519(device-private, challenge-public),
            "amnezia-awg3-ready-v1" || NUL || signed-payload-bytes)
```

The authenticated transcript contains both public keys, subscription identity,
container, configuration and validity period. The server checks its signature,
current binding/settings, capability, lifetime and proof, rejecting invalid/zero
shared secrets. The proof demonstrates possession of the original key; the private
key is not uploaded. The exchange uses the standard [X25519 primitive](https://www.rfc-editor.org/rfc/rfc7748)
and [HMAC construction](https://www.rfc-editor.org/rfc/rfc2104), with Go/OpenSSL
cross-runtime test vectors for this application protocol.

Receipts live only in the server's memory for up to 24 hours and are invalidated
by token revocation or changed settings. A restart clears them. A private root-only
Unix socket in a bounded `/run/amnezia-updates` tmpfs lets the SSH CLI query counts;
there is no network administration endpoint. The data volume and serving root
filesystem remain read-only. Old basic subscription clients/servers still exchange
schema-v1 signed settings, but cannot satisfy this new rollout readiness gate.

## Validation

```sh
bash scripts/local-tests/build-full.sh
bash scripts/local-tests/connection-updates-deploy.sh
bash scripts/local-tests/connection-updates-deploy.sh rollout
```

The final suite uses disposable nested Docker, real AWG server/client traffic,
original peer keys, signed HTTPS delivery and OpenSSL device-key receipts. It
checks both readiness gates, successful activation/fresh protected traffic and a
failure **after** publication: the original VPN returns and the rollback feed has
an increasing revision. Fake-Docker fault tests also cover old daemons, kernel
interfaces, copy/restart/publication failures and failed rollback. No production
server, user-specific domain or host Docker socket is exposed to the fixtures.
