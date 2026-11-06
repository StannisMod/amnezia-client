# Self-hosted connection updates (v1)

An administrator can distribute **updatable Amnezia profiles** for WireGuard and
userspace AWG 2/3 (`amnezia-wireguard`, `amnezia-awg2`). Ordinary profiles continue
to work unchanged. There is no web administration panel and no dependency on the
Amnezia subscription API. Control uses the existing SSH administrator credentials.

## Use

1. Disconnect the local VPN. In server **Management**, select **Set up connection
   updates**. The server must already have Docker and an address reachable by
   recipients. Setup builds a small Go service, initializes its identity once,
   and publishes HTTPS on **TCP 8443**. Allow that port in the VPS/provider firewall.
   Setup neither installs nor restarts the VPN container.
2. Under **Share**, enable **Allow connection updates**, select WireGuard or AWG,
   then share the Amnezia `.vpn` profile/QR. Existing export creates a client key
   once; subsequent updates retain that key. The initial invitation contains the
   private client profile and bearer token: share it as carefully as a VPN key.
   Native `.conf` files and older apps do not implement these updates.
3. After deliberately changing a server endpoint or protocol settings, select
   **Publish connection settings** in that protocol's settings page. Publication
   reads the live server public key, listen port and AWG interface parameters.
   It does not activate new protections, restart the VPN, create peers, or change
   client keys. Changes become effective on recipients' next connection.
4. A compatible app checks before connecting, with a ten-second total deadline.
   It can also **Update connection** manually from server Management while
   disconnected. A failed/unreachable/unverifiable update retains the cached
   profile; the user can still connect with it. Canceling connection preparation
   prevents a late network response from starting the VPN.
5. **Revoke update token** in the user sheet stops future updates for that
   client's public key and protocol. It does **not** disconnect an existing VPN
   peer. Normal **Revoke** first revokes update tokens, then removes the peer;
   if the update service is unavailable, VPN peer removal still proceeds. A pending
   token revocation is saved locally and reported. Setup/publication retries pending
   revocations before sending any new settings.

Subscriptions are per-client credentials for delivery of configuration, not a
billing feature or an expiry mechanism for the VPN itself. Copying an invitation
copies that peer's identity; issue a separate profile to each device. Issuing a
new profile generates a new token; revoked tokens are never resurrected by publish.

## Trust and permitted changes

The initial invitation pins an Ed25519 signing public key and a self-signed TLS
certificate obtained over SSH. HTTPS verifies the certificate, hostname and time;
only the pinned certificate is trusted. No SSL-error override is used. Redirects,
cookies, HTTP downgrade and cached responses are disabled. Each request uses a
fresh TLS connection; a bearer token is sent only to its original URL. Neither
private keys nor tokens enter SSH shell commands/logs. Administrative requests
containing shared AWG protection parameters use SCP inside a private directory.

An envelope contains standard base64 `payload` and `signature`. The signature
covers the exact UTF-8 payload bytes, avoiding cross-language JSON canonicalization.
The payload binds type `amnezia-connection-update`, version `1`, subscription ID,
client public key, container, decimal-string revision, issuance/expiry times and
settings. Revisions increase on publication; expiration is ten minutes. The
client rejects wrong recipients, changed content at an already accepted revision,
older revisions/issuance times, future/expired responses and oversized bodies.
An identical revision may be re-signed with a fresh validity period. Rollback
requires publishing the old settings as a **new** revision.

The settings allowlist is endpoint hostname, UDP port, server public key and
supported AWG parameters. It cannot replace client identity, PSK, interface
address, MTU, AllowedIPs, keepalive, DNS, local routing, display name, trust keys,
subscription URL/token or arbitrary native configuration/script hooks. Client
public/private keys must match cryptographically. Raw local fields are preserved;
the application commits the configuration and replay state together through the
existing secure repository, only if no intervening local edit/connection occurred.

## Server operation and recovery

Container: `amnezia-connection-updates`, image `amnezia-connection-updates:1`,
label `org.amnezia.connection-updates=1`. State volume:
`amnezia-connection-updates-state`, with the same ownership label.
The serving container mounts it read-only, has no capabilities/Docker socket,
and uses a read-only filesystem. Admin commands run separately with a writable
mount over SSH. The service has no access to VPN keys or peers. It stores signing
and TLS keys, hashed bearer tokens, public client bindings and published settings
in mode-0600 `state.json` under a private directory. Writers lock, fsync and atomically
replace the whole state file; readers see one committed snapshot. Publication
updates all active records for the chosen container in that single transaction.

Back up the volume as confidential server identity. Setup is idempotent and
rejects unrelated containers/volumes. If keys are lost, existing clients keep their
cached profiles, but cannot trust a replacement service: distribute new invitations.
Do not restore an old state snapshot and reuse its lower revision counters.
The certificate lasts ten years; automatic key/certificate rotation and feed URL
relocation are not part of v1. A server without a reachable update URL cannot
repair a broken cached VPN endpoint until the feed becomes reachable again.

Existing static profiles can now attach a keyless update invitation without
changing their device key. Controlled header protection is described in
[AWG 3 header protection](awg3-header-protection.md). The delivery service can be
upgraded through setup while keeping its identity and tokens.

This version does not enroll entirely new locally generated device keys, move peer addresses/PSKs,
provide background OS-service refresh, or support other protocols/kernel AWG1.
Desktop/mobile app checks occur in the shared UI connection flow; OS-only reconnects
use the last accepted profile. Server migration and protection rollout remain
separate steps.

## Validation

```sh
(cd client/server_scripts/connection_updates && go test -race -count=3 ./...)
cmake -S client/tests/connection-updates -B /tmp/connection-updates -G Ninja
cmake --build /tmp/connection-updates
ctest --test-dir /tmp/connection-updates --output-on-failure
bash scripts/local-tests/connection-updates-deploy.sh
bash scripts/local-tests/build-full.sh
```

The deployment check starts its own disposable nested daemon, verifies production
installation/idempotency, TLS, issue/publish, restart durability and revocation;
it never mounts the host Docker socket or accesses a production VPS. Shared Qt
controller tests additionally cover redirect/certificate rejection, cached-profile
fallback, concurrent local edits, key/routing preservation and canceled connects.
The Go-to-OpenSSL signature fixture uses only deterministic synthetic test keys.

The HTTP service bounds concurrent state readers, globally limits request rate,
and caps persisted state at 4 MiB. A full state rejects new issuance/publication
without replacing the existing file. The container also bounds memory/processes;
large fleets may require a future indexed storage backend.
