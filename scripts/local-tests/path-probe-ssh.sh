#!/usr/bin/env bash
# Read-only application SSH commands, entirely inside disposable Docker networks.
set -euo pipefail
if [[ $# -eq 0 ]]; then echo 'Usage: path-probe-ssh.sh TEST_EXECUTABLE [runner arguments...]' >&2; exit 2; fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
python3 "$repo/scripts/local-tests/test_docker_image_config_digest.py"
if ! docker image inspect amnezia-local-vpn-tests >/dev/null 2>&1; then
    docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
fi
tool_image=$(docker image inspect -f '{{.Id}}' amnezia-local-vpn-tests)
tool_os=$(docker image inspect -f '{{.Os}}' "$tool_image")
tool_arch=$(docker image inspect -f '{{.Architecture}}' "$tool_image")
snapshotter=${AMNEZIA_SSH_PROBE_CONTAINERD_SNAPSHOTTER:-true}
[[ "$snapshotter" == true || "$snapshotter" == false ]] || { echo 'Invalid SSH fixture image store' >&2; exit 2; }
echo "SSH fixture image: $tool_image"
fixture="amnezia-probe-ssh-$RANDOM-$(date +%s)"
network="$fixture-net"
transfer_tag="$fixture-image"
image_archive=$(mktemp)
cleanup() {
    docker rm -f -v "$fixture" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    docker image rm "$transfer_tag" >/dev/null 2>&1 || true
    rm -f "$image_archive"
}
trap cleanup EXIT
docker image tag "$tool_image" "$transfer_tag"
docker network create --internal "$network" >/dev/null
docker run --pull=never -d --privileged --name "$fixture" --network "$network" -e DOCKER_TLS_CERTDIR= \
    "$tool_image" --host=unix:///var/run/docker.sock --feature "containerd-snapshotter=$snapshotter" --label amnezia.test-environment=disposable >/dev/null
ready=false
for attempt in {1..60}; do
    if docker exec "$fixture" docker info >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
if [[ "$ready" != true ]]; then docker logs "$fixture"; exit 1; fi
# No registry access from the internal network: preload this local tool image.
# Export the named reference as well: containerd-backed Docker can omit the
# reference when exporting by config ID, leaving that ID unavailable to run.
docker image save "$transfer_tag" > "$image_archive"
tool_config=$(python3 "$repo/scripts/local-tests/docker_image_config_digest.py" --os "$tool_os" --arch "$tool_arch" < "$image_archive")
docker exec -i "$fixture" docker image load < "$image_archive" >/dev/null
loaded_image=$(docker exec "$fixture" docker image inspect -f '{{.Id}}' "$transfer_tag")
# Classic Docker identifies a config, containerd identifies a manifest/index.
# Inspect JSON also varies across engine API versions. Compare the actual
# archived config, which includes runtime settings and ordered rootfs digests.
loaded_config=$(docker exec "$fixture" docker image save "$transfer_tag" | python3 "$repo/scripts/local-tests/docker_image_config_digest.py" --os "$tool_os" --arch "$tool_arch")
echo "SSH fixture config identity: $tool_config -> $loaded_config"
[[ "$loaded_config" == "$tool_config" ]] || { echo 'SSH fixture archived config changed during transfer' >&2; exit 1; }
echo "SSH fixture loaded image: $loaded_image (containerd=$snapshotter)"
for kind in wireguard awg2; do
    iface=wg0; addresses='ip address add 10.77.0.9/24 dev wg0; ip address add fd77::1/64 dev wg0'
    if [[ "$kind" == awg2 ]]; then iface=awg0; addresses='ip address add fd88::9/64 dev awg0'; fi
    docker exec "$fixture" docker run --pull=never -d --name "amnezia-$kind" --network none --cap-add NET_ADMIN \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 --entrypoint sh "$loaded_image" -ec \
        "ip link add $iface type dummy; $addresses; ip link set $iface up; touch /ready; exec sleep 300" >/dev/null
    ready=false
    for attempt in {1..30}; do
        if docker exec "$fixture" docker exec "amnezia-$kind" test -f /ready >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    if [[ "$ready" != true ]]; then docker exec "$fixture" docker logs "amnezia-$kind"; exit 1; fi
done
docker exec "$fixture" sh -ec 'ssh-keygen -A >/dev/null 2>&1; mkdir -p /run/sshd; echo root:synthetic-probe-fixture | chpasswd; /usr/sbin/sshd -p 2222 -o PermitRootLogin=yes -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no'
export AMNEZIA_SSH_PROBE_HOST
auto_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$fixture")
[[ "$auto_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "No fixture IPv4 address" >&2; exit 1; }
AMNEZIA_SSH_PROBE_HOST="$auto_ip"
export AMNEZIA_SSH_PROBE_NETWORK="$network" AMNEZIA_SSH_PROBE_PORT=2222 AMNEZIA_SSH_PROBE_PHASE=present
export QT_QPA_PLATFORM=offscreen
timeout 90 "$@" realAdminProbeAddressRead
docker exec "$fixture" docker stop amnezia-wireguard >/dev/null
export AMNEZIA_SSH_PROBE_PHASE=missing
timeout 90 "$@" realAdminProbeAddressRead
echo 'PASS: real SSH, active IPv4/IPv6 interface discovery, old admin profile migration and missing-container failure'
