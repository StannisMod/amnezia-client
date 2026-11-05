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
