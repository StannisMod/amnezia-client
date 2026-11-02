# Protocol software updates

Self-hosted administrators can select **Update protocol** in the protocol page
for a standard WireGuard or AmneziaWG 3 container. Disconnect the local VPN
first; this also avoids losing the management SSH connection during cutover.
The operation runs off the UI thread and blocks repeated requests in this client.
Plan a maintenance window: all peers briefly lose connectivity at cutover.

This action updates the container software without changing connection settings.
It does not call the installation/configuration generators, clear cached client
profiles, revoke a client, or write to the local server repository. In particular,
the domain endpoint introduced in PR #7 remains unchanged.

## Transaction

1. Require a running VPN interface and a standard container layout: default
   bridge networking, one UDP port published unchanged on all IPv4 interfaces,
   no custom mounts other than `/lib/modules`, and a supported restart policy.
   AmneziaWG additionally requires the AWG 3 header protection parameter on the
   server, regardless of the version recorded in the client.
2. Record the original Docker metadata and tool versions (also the userspace
   daemon version for AWG). Build the bundled Dockerfile with `--pull` while the
   original VPN keeps serving. Record the target versions and immutable image ID.
   An unsupported/missing binary or failed build leaves the original running.
3. Disable automatic restart of the old container, stop it, and copy the entire
   `/opt/amnezia` tree, including keys, protocol parameters, peer config,
   `clientsTable`, and the already configured startup script. Reject concurrent
   config changes detected while preparing the update.
4. Retain the old container under a unique backup name. Create its replacement
   from the pinned image, restore the state tree, and attach the original Docker
   networks. No new key material is generated.
5. Require a live VPN interface and an effective `showconf` matching the original
   runtime. Compare each peer's PSK/allowed IPs with its public key, ignoring only
   roaming endpoints and ordering. Repeat validation after a container restart.
6. Restore the original restart policy. Keep the stopped original container and
   protected on-server snapshot for recovery; do not prune them automatically.

A server-side per-container `flock` serializes this operation across clients.
Other administrative operations do not yet participate in this lock: do not edit
users/settings or remove containers from another client during the update.

## Failures and recovery

Ordinary command failure and HUP/INT/TERM invoke rollback. Remove the replacement
if created, rename the original back, restore its restart policy, start it, and
require the original VPN interface to return before reporting successful rollback.
If rollback cannot be verified, the app reports that the server needs attention.
Missing terminal output/SSH loss is an **unknown outcome**, never reported as a
successful update or a confirmed rollback.

Recovery files are root-only in `/var/lib/amnezia/updates/<container>-<uuid>/`:
`result`, `update.log`, Docker metadata, version reports, the target image ID,
and `state/` containing the saved tree. Treat the directory as secret material.
The retained container is `<container>-backup-<uuid>`, stopped with restart policy
`no`. Confirm the active/backup container IDs and inspect `result` before a manual
recovery or retry. Keep only one container bound to the original port.

Power loss, Docker daemon failure, SIGKILL, or host reboot can interrupt rollback;
there is no persistent recovery supervisor in this version. Retained snapshots
and containers require manual cleanup after acceptance, and consume disk space.

## Compatibility and validation

The first version supports updates within the existing WireGuard/AWG 3 settings.
It does **not** migrate AWG 1/2 to AWG 3, replace protocol parameters, or deliver
new configs to clients. Version strings are recorded for diagnosis; readiness is
based on successful configuration application, identity preservation and restart,
not a comparison of upstream version labels (the AWG daemon uses a date version).
Custom container layouts and stopped/broken source containers are rejected.

`client/tests/protocol-update/test_transaction.py` runs the production shell with
a Docker boundary that injects build, copy, rename, create, start, restart,
network, runtime state and rollback failures, plus HUP and concurrent requests.
It needs neither Docker nor root.

`client/tests/protocol-update/acceptance.py` runs only on disposable GitHub Actions
VMs. The matrix uses the production WireGuard/AWG Dockerfiles and startup scripts,
establishes real peer traffic, updates without touching the client's profile,
checks every state file, and injects an image that stays running without a VPN
interface to verify rollback and restored client traffic. Full product builds
remain necessary to validate the C++/QML integration on supported platforms.
