#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
binary=${1:?Usage: protocol-update-ssh.sh /absolute/path/to/test_server_edit}
python3 "$repo/server/ipv6/lab/test_ipsec_update_diagnostics.py"
qt_root=${AMNEZIA_PROTOCOL_UPDATE_QT_ROOT:-/opt/Qt/6.10.1/gcc_64}
image=${AMNEZIA_PROTOCOL_UPDATE_IMAGE:-amnezia-protocol-update-qt:local}
mounts=(--mount "type=bind,source=$repo,target=/src,readonly")
trust_env=()
if [[ -r /etc/ssl/certs/ca-certificates.crt ]]; then
    # The nested daemon must use the runner's configured trust roots too
    # (including a runner-managed registry proxy CA). Never disable TLS or
    # import a certificate downloaded from the failing endpoint.
    host_ca=$(realpath /etc/ssl/certs/ca-certificates.crt)
    mounts+=(--mount "type=bind,source=$host_ca,target=/run/amnezia-host-ca.crt,readonly")
    trust_env+=(-e SSL_CERT_FILE=/run/amnezia-host-ca.crt)
fi
if [[ -n ${AMNEZIA_PROTOCOL_UPDATE_BUILD_VOLUME:-} ]]; then
    mounts+=(--mount "type=volume,source=$AMNEZIA_PROTOCOL_UPDATE_BUILD_VOLUME,target=/work,readonly")
else
    binary=$(realpath -- "$binary")
    [[ -x "$binary" && -d "$qt_root/lib" ]] || { echo 'Compiled test and Qt SDK are required' >&2; exit 2; }
    # Retain absolute build/SDK paths used by the executable's runtime search paths.
    build_root=$(realpath -- "$(dirname -- "$binary")/../..")
    mounts+=(--mount "type=bind,source=$build_root,target=$build_root,readonly")
    mounts+=(--mount "type=bind,source=$qt_root,target=$qt_root,readonly")
fi
docker build --network host -f "$repo/scripts/local-tests/Dockerfile.protocol-update-qt" \
    --build-arg "QT_IMAGE=${AMNEZIA_PROTOCOL_UPDATE_QT_IMAGE:-ubuntu:22.04}" \
    --build-arg "DAEMON_IMAGE=${AMNEZIA_PROTOCOL_UPDATE_DAEMON_IMAGE:-docker:29-dind}" \
    -t "$image" "$repo/scripts/local-tests"
runner_name="amnezia-ipsec-ssh-$(date +%s)-$RANDOM"
runner=''
cleanup() {
    if [[ -n ${runner:-} ]]; then docker rm -fv "$runner" >/dev/null; fi
}
trap cleanup EXIT
runner=$(docker run -d --privileged --name "$runner_name" --label amnezia.local-tests=ipsec-ssh \
    --dns 1.1.1.1 --dns 8.8.8.8 "${mounts[@]}" \
    "${trust_env[@]}" \
    -e LANG=C.UTF-8 -e QT_QPA_PLATFORM=offscreen \
    -e "QT_QPA_PLATFORM_PLUGIN_PATH=$qt_root/plugins/platforms" \
    -e "LD_LIBRARY_PATH=$qt_root/lib" \
    "$image" --host=unix:///var/run/docker.sock --storage-driver=vfs \
    --feature containerd-snapshotter=false --dns=1.1.1.1 --dns=8.8.8.8 \
    --label amnezia.test-environment=disposable)
ready=false
for attempt in {1..60}; do
    if docker exec "$runner" docker info >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
if [[ $ready != true ]]; then docker logs "$runner"; exit 1; fi
docker exec "$runner" test -x "$binary"
docker exec "$runner" docker pull amneziavpn/ipsec-server@sha256:080673496751055c76389c76d87329f033ad7b514f52a776651617ba14179540
docker exec "$runner" python3 /src/server/ipv6/lab/test_ipsec_update.py --qt-update-test "$binary"
