# Local Docker validation

From the repository root:

```sh
bash scripts/local-tests/run.sh all
bash scripts/local-tests/build-full.sh
```

The first command runs the production-shell fault-injection tests, Qt endpoint
and routing contract tests, and real WireGuard/AWG update/rollback acceptance.
Use `qt`, `vpn`, `wireguard`, `awg` or `awg2` instead of `all` to select a suite.
`awg2` runs both real AWG 2-to-3 compatible-update profiles; `all`/`vpn` also
include standard WireGuard and protected AWG 3 updates. The old daemon/tools are
built from pinned source commits in `client/tests/protocol-update/Dockerfile.awg2`.

The second command builds the Linux application, service and Qt regression tests
with Go 1.27.1 and Qt 6.10.1, then runs the regression suite. It downloads SDKs
and Conan dependencies on the first run. Initialize the pinned Linux submodules
before building:

```sh
git submodule update --init --depth 1 client/3rd/SortFilterProxyModel client/3rd/qtkeychain
```

Full-build SDK images are reused when present. After changing their Dockerfiles,
use `bash scripts/local-tests/build-full.sh --rebuild` to rebuild the toolchain.

VPN tests run a separate privileged Docker-in-Docker container per protocol.
The host Docker socket is never mounted inside it. Test ports, `host` networking
used by the synthetic client, keys, snapshots and container names all belong to
the nested environment. The wrapper removes its generated runner and anonymous
volumes on exit. It does not remove existing host containers or run global prune.
The source repository and kernel modules are mounted read-only.

Image builds and the full-build container use the host network to download
dependencies correctly when the host uses a VPN DNS proxy with synthetic IPs.
The VPN runners retain a separate network and use public DNS. No host firewall
or Docker daemon settings are changed.

Full-build source copies, dependencies and artifacts live in the dedicated
`amnezia-local-full-build` Docker volume. SDK/test images remain cached locally.
The full-build source copy is writable so Qt translation tools cannot alter the
original checkout. Linux tests here do not replace Windows or Apple SDK builds.

Self-hosted signed connection updates have a separate disposable deployment check:

```sh
bash scripts/local-tests/connection-updates-deploy.sh
```

It tests the production installer, pinned HTTPS, publication durability and token
revocation. Go race tests run from `client/server_scripts/connection_updates`;
client/controller security tests are included in the full build's CTest suite.
See [connection updates](../../docs/selfhosted-connection-updates.md).

Controlled AWG 3 header protection has a real server/client acceptance suite:

```sh
bash scripts/local-tests/connection-updates-deploy.sh rollout
```

It checks device-key readiness, unchanged identities, protected fresh traffic and
rollback after signed publication. The full SDK wrapper also supports linked Git
worktrees using a private copy of their Git metadata; host metadata stays read-only.

The unsigned iPhoneOS ARM64 build uses the standard
`macos-15-intel` host when the hosted ARM64 pool cannot acquire runners.
Both native macOS CPU lanes and the ARM64 race-CAS/performance diagnostics
remain enabled.

### Server migration

`bash scripts/local-tests/migration-scenario.sh` creates two disposable Docker
hosts and checks unchanged WireGuard/AWG clients, DNS through the tunnels,
original signed HTTPS subscription tokens/certificate, cutover and rollback
without lowering replay counters. It uses dedicated synthetic-data cache volumes
`amnezia-migration-acceptance-source` and `amnezia-migration-acceptance-target`.
No host Docker socket is mounted inside the fixtures. See
[server migration](../../docs/server-migration.md) for the app flow and limits.
`python3 client/tests/migration/test_agent.py` checks archive boundaries and replay
floors; `bash scripts/local-tests/migration-ssh.sh` checks actual SSH/SFTP.

`bash scripts/local-tests/migration-relay.sh` checks the app's actual new-host pull
path: old SSH is blocked to an administrator actor and reachable only from the
new host, with no archive downloaded by the app. It also checks a detached copy,
reviewed host keys before password auth, both authentication methods and direct
rollback preserving the signed revision floor.

### Existing-profile probe address over SSH

The ordinary connection-updates Qt target also checks local pending-export
storage. A separate process reads the record before the writer is destroyed;
stale replacements and malformed storage are refused. A child process uses an
explicit INI backend with an impossible directory to verify write failure on
all platforms without touching real settings. Pending secrets are excluded from
backup/restore and full-access exports and follow the existing SecureQSettings
encryption policy (Linux desktop currently disables that policy). The storage
API is a prerequisite; it does not yet resume the export pipeline or reconcile
server operations. Compare-and-set serialization covers one settings instance,
not independent application processes.


The same required fixture runs the packaged `install.sh` helper deployment against
already running kernel WG and userspace AWG containers, twice. It checks immutable
container identity, process/start time, native configuration, stored configuration,
interface addresses, executable permissions and the durable ownership receipt.
The production connection-update installer uses this deployment before starting
or upgrading delivery. Helper installation does not restart the VPN. Unknown
existing executables are refused; upgrading relies on the private receipt rather
than adopting an observed hash. Go tests cover interrupted publication on either
side of rename, foreign replacement, stale expectations and pending transactions.
This does not prove original TCP survival or close the legacy-writer bootstrap race.
Managed-helper disappearance is tested separately after its transaction journal
has been removed: the app must report a handled error and preserve the config.
Ownership receipts and the installer lock marker prevent legacy fallback. The
legacy compatibility phase hides both managed markers as well as the executable
inside the disposable fixture, representing a genuinely unmanaged old server.
Native state comparison preserves all peer associations/fields while ignoring
only unspecified section/field enumeration order; stored config remains byte exact.


After building the Linux Qt tests, run:

```sh
bash scripts/local-tests/path-probe-ssh.sh deploy/build/client/tests/test_connection_updates_controller
```

The test creates an internal Docker network and a disposable SSH server with its
own Docker daemon. It preloads locally built images; the internal daemon does not
pull from a registry. The `wg0` interface uses kernel WireGuard, and `awg0` uses
the actual userspace AWG daemon from a digest-pinned image. Synthetic peers cover
individual IPv6 assignments, IPv4-only peers and peers without addresses. Native
SSH discovery must reject ambiguous IPv6 subnets and stopped containers without
changing its output.

The fixture also builds the production signed-update service. The application
exports an invitation for an existing WG/AWG key over its normal SSH admin path,
attaches it to a user profile, fetches the signed update over certificate-pinned
HTTPS and verifies the assigned IPv6 while preserving its private key and routes.
It also creates a fresh peer through the normal configurator, verifies native
live peer synchronization and the exported dual-stack profile, then confirms a
signed withdrawal removes its managed IPv6 without changing the generated key.
The same actual export case then revokes the fresh peer through UsersController.
Its key is deliberately mentioned in an earlier Interface comment. Only the
exact PublicKey peer may be removed; the Interface bytes, public server settings
and all other native peer assignments must remain unchanged. This exercises the
production revocation path, while transaction/locking coordination across all
writers remains separate unfinished work.
The production configuration helper is also exercised inside both containers:
private journal creation, operation identifiers, stage/status/commit/rollback,
rejection of unrelated or completed operations and preservation of live peer sets.
The helper can apply the staged native protocol configuration with `syncconf`
and restore both the original file and live peer routes with `rollback-live`.
Tests cover rollback before apply, an actual route change, and recovery after a
native parser rejects malformed input. An IPv4-only migration is planned and staged, then the actual server IPv6 and
per-peer routes are applied together. Rollback removes only the address added by
the operation and preserves preexisting and unrelated addresses. Commit is
rejected before successful live application. The production signed-feed admin
executable then publishes the key-bound assignments conditionally, discards the
first reply, recovers its persisted operation receipt and retries without another
revision change. A separate conditional withdrawal advances revisions. Go tests
also verify the signed HTTPS payload and preservation of individual settings,
keys, tokens and delivery identity. This controlled fixture has no active clients
using the newly published IPv6 addresses: its subsequent backend rollback is not
a safe recovery policy after publication to real clients. Coordinating egress,
publication and compatible recovery remains unfinished. The durable journal also
backs up the actual native configuration. IPv6 staging rejects stale on-disk
identities. A native route edit between stage and first apply is also rejected
before activating IPv6; rollback of that unapplied transaction preserves the
independent edit. A durable native-write intent distinguishes a snapshot from an
attempted protocol modification. Rollback can restore the working protocol even when the old file
is invalid. Dynamic peer endpoints are omitted from the backup so roaming to a
new outer address is preserved during rollback. Its sidecar lock protects participating
writers; existing writers that ignore it still need integration.
The fresh-peer export also runs against native peer order. IPv4 allocation sorts
all IPv4 entries in AllowedIPs numerically, including mixed IPv6-first lists;
the ordinary Qt format suite checks every permutation of a multi-peer example.
The existing asynchronous probe-profile migration remains covered. This validates
management and signed delivery; it does not send encrypted user traffic or prove
Internet egress. Keys and credentials are synthetic; no host VPN or production
server is used. Cleanup removes the daemon, its volumes and the internal network.

This is required by the Linux routing build/package workflows. The same Qt test
is skipped in a plain CTest run without the fixture environment; that skip does
not substitute for the separate SSH integration step.

The ordinary AWG MTU workflow also runs
`python3 server/ipv6/lab/test_docker_prepare.py --report ipv6-docker-prepare.json`.
This uses a separate Docker daemon with no external network. After preparing the
production IPv6-only bridge, it attaches running WG/AWG-named fixture containers
using the production helper. The original IPv4 endpoint, all IPv4 routes and
resolver file must remain unchanged. A TCP socket opened before attachment must
exchange another payload afterward, and Docker DNS must resolve the same peer.
Repeating attachment must preserve both network endpoints. These fixtures test
container networking; they do not run an encrypted tunnel or prove Internet IPv6
egress. The helper reports egress as unverified and never detaches automatically
after a failed preservation check.

The kernel IPv6 forwarding regression also invokes the maintenance branch of
all three packaged startup scripts. On a script version that includes this
branch, `bash /opt/amnezia/start.sh --amnezia-prepare-ipv6-forwarding wg0`
(`awg0` for current AWG) prepares rules without running tunnel teardown/startup.
The caller must verify that the installed script supports the branch before
using it: an old startup script does not support this command. Invalid arguments
and missing tunnel IPv6 must fail without adding rules. Repeated calls preserve
foreign rules and the IPv4 firewall/routes; an original IPv4 TCP session stays
open while actual IPv6 forwarding/NAT is verified against a local origin.
This additive preparation does not provide a whole-operation rollback or prove
Internet reachability; automatic migration still needs its coordinator.

The production transaction helper exposes `prepare-forwarding`, bound to the
pending operation. It requires the IPv6 native configuration to be applied,
checks the candidate file and actual native baseline, and verifies the installed
startup prefix against the packaged shared resource hash. It executes only that
verified prefix snapshot through Bash stdin with a fixed environment, never the
installed startup body. Old/modified scripts are rejected; automatic installation
of a compatible prefix on old servers remains part of the unfinished migration
coordinator. The result means preparation succeeded at that invocation; it is not
a durable Internet-readiness receipt. The ordinary SSH regression exercises old
script rejection, missing-route failure and idempotent real WG/AWG preparation.

`startup-file-transaction` provides stage/status/commit/rollback for the fixed
`/opt/amnezia/start.sh` path in WG/AWG containers. A stage accepts only a known
verified prefix followed by the exact old Bash script body; it rejects changing
interpreter options, body edits, duplicate prefix installation and all live
protocol actions. The existing durable private journal, exact-file precondition,
operation nonce and conflict-preserving rollback apply. It never executes the
startup file. The ordinary real SSH regression upgrades an old synthetic script,
recovers the stage result, rolls back to exact old bytes, then commits the upgrade
and prepares forwarding without executing the startup body. This supplies the
maintenance capability; automatically coordinating it with migration, and
ensuring IPv6 forwarding also runs after a future restart of old startup bodies,
remain separate completion requirements.

Startup staging additionally permits one recognized boot transformation for
known WG/current-AWG startup preludes: insert the existing IPv6 forwarding call
immediately after the configured `*-quick up` block. It validates the complete
prelude fingerprint, including the upstream AWG variant without the MTU stop
block. Only the IP in the known commented ifconfig line is normalized for
recognition; deployed body bytes are preserved. Unknown/custom/heredoc preludes
and unrelated edits are rejected. Go regressions cover canonical/deployed inputs,
maintenance-only upgrades, idempotence and execution order with local command
doubles. The real SSH suite stages and rolls back the transformed actual
startup templates. It does not restart the container, so full reboot acceptance
and IPv4 availability when IPv6 preparation fails remain unfinished requirements.

The IPv6 workflow also runs `run_boot.sh` for wireguard, awg and awg-legacy.
These tests execute the actual packaged startup bodies and real kernel IPv4
forwarding/NAT with IPv6 configured but no IPv6 default route. Tunnel quick
commands and final supervisor/keepalive commands are explicit test doubles;
this does not replace real tunnel/container restart acceptance. Startup must
continue, report IPv6 preparation failure, install IPv4 forwarding, and allow
both the original NAT-tracked TCP socket and a new TCP connection. A private
negative control reinstating the old fatal exit fails this test. Boot candidate
validation can also replace that exact old fatal call in recognized startup
bodies without changing unrelated lines. Retrying IPv6 preparation when a
previously missing route returns still needs the migration lifecycle coordinator.

The private-Docker IPv6 preparation regression now requires an actual additional
IPv6 endpoint, its nonempty address and membership in the owned bridge. Checking
only unchanged IPv4 state is insufficient: an earlier Docker template treated a
missing map entry as a truthy zero struct and skipped attachment. The production
helper now checks the indexed endpoint's nonempty Name.

That regression also executes real kernel WireGuard and userspace AWG startup
scripts, real quick commands and the actual MTU supervisor. An unchanged native
client checks new 64 KiB TCP exchanges over IPv4 and IPv6 after initial startup,
container restart with the IPv6 bridge, and restart after removing that bridge.
It verifies interface kinds, persistent keys/configuration/addresses, the original
Docker IPv4 endpoint and exact IPv6 membership. In phases with IPv6 egress it
also checks forwarding/NAT rules and encrypted TCP through NAT66 to an independent
local IPv6 origin; that origin must observe the server's bridge address. No tunnel
or daemon command is replaced in this test. It verifies new connections after a
real restart, separately from the existing tests of retained connections during
live reconfiguration. Public Internet IPv6 reachability is not tested.

Startup migration recognizes the exact historical shared forwarding resource
from commit `348218b` (kept unchanged in the server helper's testdata) as well as
the current resource. It removes recognized definitions before adding the current
block, preserving the original startup body. This also repairs files where a
previous maintenance update prepended the current block before the historical
one. Unknown function definitions are refused rather than left to shadow the new
functions. The ordinary signed-service suite checks fingerprints, mixed prefixes,
body preservation and combined boot-hook repair. The required SSH regression
performs real stage/rollback/commit of the historical file for WG and AWG.

Normal native protocol mutations can use `stage-live` followed by operation-bound
`apply-commit`. Staging captures the native baseline under the file lock and
requires it to agree with the original file. Applying rechecks the snapshot;
commit rechecks the actual native candidate before clearing the journal. A
separate earlier `apply` does not bypass that commit check. Concurrent native
key/route edits cause refusal with the journal retained. The combined operation
holds the lock through synchronization and commit; failed synchronization stays
recoverable through the existing live rollback.

This path preserves quick-only settings (Address, MTU, DNS, Table and hooks),
which syncconf does not apply. IPv6 address migration uses its separate actor.
The real WG/AWG regression injects native route edits before apply and before
commit, verifies refusal/preservation, then checks successful apply-commit and
failed-parser recovery. Client-side creation/revocation use these transactions
when a compatible helper is installed; automatic helper installation and the
remaining writers still need migration coordination.

The SSH layer checks the `native-mutation-v1` capability before staging, uploads
JSON only through a private temporary directory, and validates operation IDs and
file hashes. If the stage reply is lost, it can recover the matching journal. If
the apply-commit reply is lost, `check-live` confirms an exact committed file and
native state under the lock; a pending journal is never reported as committed.
Repeating an already-applied apply-commit verifies and commits without applying
again. Errors on this path never fall back to direct file upload. An absent
helper with a pending journal is also refused; a clean old server without a
helper retains the existing behavior.

The ordinary SSH fixture runs fresh creation/revocation in both managed and
legacy modes. In managed mode it also blocks a conflicting app writer, temporarily
hides the helper while a journal exists, and deliberately discards successful
stage/commit responses using `protocol-helper-loss.py`. Marker assertions require
both faults to have occurred before accepting the app's successful export. The
proxy executes only in the disposable fixture and forwards the production binary;
it does not simulate an actual SSH connection loss. All previous native, signed
update, Interface-preservation and rollback checks remain enabled.
