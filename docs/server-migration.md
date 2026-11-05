# Move a server while keeping its domain

In **Server → Management → Move server**, enter the new server's SSH address,
port, login and password or unencrypted private key. Compare both SSH SHA256
fingerprints with the server consoles before accepting them. The app connects
only to the new server. The new server opens the old server's SSH connection and
pulls the archive directly; the administrator device never relays backup data.
This supports an old server whose SSH is blocked from the administrator's network
but remains reachable from the new server. Subsequent connections use reviewed
literal IP addresses and host keys, including after DNS changes. Credentials are
not sent during fingerprint discovery.

The first version supports running standard `amnezia-wireguard`,
`amnezia-awg2`, optional `amnezia-dns` and optional
`amnezia-connection-updates`. Both hosts need Linux, a rootful local Docker daemon,
Python 3.9 or newer, and root or passwordless sudo access. The new host also
needs the OpenSSH client (`ssh` and `ssh-keyscan`). Encrypted SSH private
keys must be unlocked before using this flow. The target must use the same CPU
architecture and have the required container names, ports, volume and DNS network
available. The target SSH address must resolve to IPv4 in this version. Custom
networks, mounts, active unsupported Amnezia protocols and nonstandard restart
policies are rejected. Unrelated resources are never removed to make room.

All existing client VPN endpoints must already use the domain you are keeping.
A numeric subscription URL cannot follow a domain change: the source subscription
service must already use a DNS name too. Set this up before issuing profiles.
Migrating a server cannot change offline devices' immutable numeric URLs.

1. Disconnect the administrator app's VPN. Keep both VPSs available. Do not edit
   users, protocols, DNS configuration or subscriptions during the move. Before
   starting, reduce DNS TTL and wait out the previous TTL if a short cutover is
   needed. Open the existing VPN UDP ports and, when used, TCP 8443 on the target.
2. First approve the new server's SSH fingerprint. It discovers the old server's
   fingerprint without authenticating; compare and approve that fingerprint too.
   Only then does the app send the old server's SSH credentials to the new host,
   through its pinned SSH connection. The new host uses temporary mode0600 key or
   password files under a root-only directory; credentials never appear in process
   arguments, environment values, logs or job results, and are removed when the
   operation finishes. Passwords use OpenSSH ASKPASS; SSH agent forwarding is off.
   The new server is a trusted recipient of these administrative credentials.
   Copying runs as a detached job on the new server and continues if the app's
   control connection drops or the app exits. Reopen the saved operation to poll
   its result. Private snapshots are streamed directly over the new-to-old pinned
   SSH connection, size bounded and SHA256 checked; no registry push is used.
   The source continues serving, with brief Docker commit pauses.
3. The candidate starts on the target with automatic restart disabled. The app
   verifies the original configuration, live peers and delivery identity. Temporary
   test peers exercise each VPN through the target's published UDP port from the
   old host, including DNS through the tunnel when installed. Existing device
   private keys are never used for these probes. HTTPS is checked externally using
   the original certificate and control hostname. Probe peers and clients are
   removed on completion; interrupted probes can be cleaned during recovery.
4. After those checks pass, update the VPN domain and the subscription domain's
   A/AAAA records to the target. Remove stale AAAA records when the target has no
   IPv6 endpoint. Choose **DNS updated — switch servers**. Every address returned
   by the administrator device's resolver must select the target. Other devices'
   cached records may still need their TTL to expire.
5. The source is checked again for changes, then its original containers are
   stopped with automatic restart disabled. The target's original restart policies
   are restored, and this app's management credentials switch to the new IP.
   Existing VPN profiles, domain names, keys, peers, PSKs, addresses, local DNS and
   routing choices remain intact. Keep both VPSs until clients reconnect.

A source configuration or peer change invalidates the snapshot and prevents
cutover. Files and semantic live configuration are checked; roaming peer endpoints,
DNS process IDs and DNSSEC trust-anchor refresh metadata are runtime state. DNS
configuration itself is preserved. Temporary readiness receipts, DNS caches and
live VPN sessions are recreated, rather than copied as persistent identities.

## Recovery and rollback

The app saves one migration operation in its settings and each host maintains a
root-only journal. The app journal includes the credentials needed for recovery;
it receives the same platform-dependent storage protection as ordinary server
credentials and is excluded from application backup exports. Linux desktop's
existing settings implementation does not encrypt server credentials or this
journal. Do not share the settings directory. No passwords, peer secrets, archive
contents or private keys are printed in operation messages.

After an interrupted control connection or SSH reply, use **Check saved operation**.
While the detached pull is running, the saved job can be polled without sending
source credentials again. Source commands, cutover, rollback and finalization all
continue through the new host; direct old-host SSH from the app is never needed. A
journaled stop can be retried without replacing containers. A verified candidate's
external probe can be repeated. A partial import can be aborted; cleanup is
restricted to this operation's unpredictable resource labels. An unknown result
is never reported as success. Power failure or loss of either host may require
operator recovery; the flow does not install an independent supervisor.

**Restore source server** stops the target and restarts the original source
containers. Restore the old DNS records before reconnecting. After activation,
rollback first transfers the target's current subscription state back to the
stopped source: signing/TLS identity, token bindings, revocations and counters are
validated, versions cannot decrease, and revoked tokens cannot be revived. This
preserves a newer version already accepted by an offline client. If VPN identities
or DNS configuration were edited on the target, automatic rollback refuses to
restore a different configuration; reconcile it manually. Concurrent administrative
edits during migration are unsupported.

**Finish and forget rollback credentials** removes the local journal and transfer
archives, retaining a small host audit marker. Unused source snapshot images are
removed without force. Original source containers and stopped target rollback
containers are retained; the VPS itself is never deleted. Target snapshot images
in use are retained because they contain the running configuration. Finishing
ends the app's automatic rollback/recovery for this operation.

## Local verification

```sh
python3 client/tests/migration/test_agent.py
bash scripts/local-tests/migration-ssh.sh
bash scripts/local-tests/migration-scenario.sh
bash scripts/local-tests/migration-relay.sh
bash scripts/local-tests/build-full.sh
```

The scenario creates two labelled disposable Docker-in-Docker hosts; it never
mounts the host Docker socket inside them. Dedicated fixture volumes cache only
synthetic test data. It proves unchanged WG and AWG client traffic before/after
migration, DNS through each tunnel, temporary external probes, the old HTTPS
certificate and bearer token, Ed25519 verification, refusal of source drift,
retry after a lost cutover reply, and rollback after publication without lowering
a replay floor. Reserved `example.test` names are used in fixtures.

The relay acceptance additionally blocks old SSH from an administrator network
actor while allowing it from the new host. It proves unauthenticated discovery,
wrong-key rejection before password authentication, real password and key auth,
a detached pull after its start command exits, direct archive/rollback transfer,
unchanged client traffic and removal of temporary source credentials. Cold test
images include OpenSSL and OpenSSH explicitly rather than relying on a cached image.

Recovery additionally distinguishes an interrupted target stop and an interrupted
source restart. Repeating rollback after its final reply was lost reconciles the
actual container/restart-policy state and the applied store digest; it does not
import an older store into a source that has already restarted. Finalization
checks that no detached worker is active before removing pending worker/app
credential requests, temporary SSH material and private Python caches.

Subscription administration uses the immutable image ID of the owned running
service container with registry pulls disabled. It does not require a named
image tag on a freshly migrated target. The acceptance test executes the same
C++ command builder used by the app over pinned SSH for info, issue, publish and
revoke, while asserting that the old image tag is absent.
