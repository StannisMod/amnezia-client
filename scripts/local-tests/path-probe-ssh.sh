#!/usr/bin/env bash
# Read-only application SSH commands, entirely inside disposable Docker networks.
set -euo pipefail
if [[ $# -eq 0 ]]; then echo 'Usage: path-probe-ssh.sh TEST_EXECUTABLE [runner arguments...]' >&2; exit 2; fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
python3 "$repo/scripts/local-tests/test_docker_image_config_digest.py"
if ! docker run --pull=never --rm --network none --entrypoint sh amnezia-local-vpn-tests -ec 'command -v wg >/dev/null; command -v awg >/dev/null; command -v amneziawg-go >/dev/null' >/dev/null 2>&1; then
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
docker exec "$fixture" sh -ec 'mkdir -p /dev/net; test -c /dev/net/tun || mknod /dev/net/tun c 10 200'
for kind in wireguard awg2; do
    iface=wg0; addresses='ip address add 10.77.0.9/24 dev wg0; ip address add fd77::1/64 dev wg0'
    if [[ "$kind" == awg2 ]]; then iface=awg0; addresses='ip address add fd88::9/64 dev awg0'; fi
    setup="ip link add $iface type dummy"
    if [[ "$kind" == wireguard ]]; then
        setup='ip link add wg0 type wireguard; umask 077; wg genkey > /tmp/private; a=$(printf DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD | base64 | wg pubkey); b=$(printf BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB | base64); c=$(printf CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC | base64); wg set wg0 private-key /tmp/private peer "$a" allowed-ips 10.77.0.2/32,fd77::2/128 peer "$b" allowed-ips 10.77.0.3/32 peer "$c" persistent-keepalive 25; rm /tmp/private'
    fi
    if [[ "$kind" == awg2 ]]; then
        setup='mkdir -p /dev/net; test -c /dev/net/tun || mknod /dev/net/tun c 10 200; amneziawg-go awg0; umask 077; awg genkey > /tmp/private; a=$(printf DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD | base64 | wg pubkey); b=$(printf BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB | base64); c=$(printf CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC | base64); awg set awg0 private-key /tmp/private peer "$a" allowed-ips 10.88.0.2/32,fd88::2/128 peer "$b" allowed-ips 10.88.0.3/32 peer "$c" persistent-keepalive 25; rm /tmp/private'
    fi
    docker exec "$fixture" docker run --pull=never -d --name "amnezia-$kind" --network none --cap-add NET_ADMIN --cap-add MKNOD --device /dev/net/tun \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 --entrypoint sh "$loaded_image" -ec \
        "$setup; $addresses; ip link set $iface up; touch /ready; exec sleep 300" >/dev/null
    ready=false
    for attempt in {1..30}; do
        if docker exec "$fixture" docker exec "amnezia-$kind" test -f /ready >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    if [[ "$ready" != true ]]; then docker exec "$fixture" docker logs "amnezia-$kind"; exit 1; fi
done
# Use the production signed-delivery binary and Docker admin command path.
docker build --network host -t amnezia-updates-ssh-tests "$repo/client/server_scripts/connection_updates"
docker image save amnezia-updates-ssh-tests | docker exec -i "$fixture" docker image load >/dev/null
auto_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$fixture")
[[ "$auto_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "No fixture IPv4 address" >&2; exit 1; }
printf '{"host":"%s"}' "$auto_ip" | docker exec -i "$fixture" docker run --rm -i --network none \
    --mount type=volume,source=amnezia-connection-updates-state,target=/data amnezia-updates-ssh-tests init >/dev/null
docker exec "$fixture" docker run -d --name amnezia-connection-updates -p 8443:8443 \
    --mount type=volume,source=amnezia-connection-updates-state,target=/data amnezia-updates-ssh-tests >/dev/null
docker exec "$fixture" sh -ec 'ssh-keygen -A >/dev/null 2>&1; mkdir -p /run/sshd; echo root:synthetic-probe-fixture | chpasswd; /usr/sbin/sshd -p 2222 -o PermitRootLogin=yes -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no'
export AMNEZIA_SSH_PROBE_HOST
auto_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$fixture")
[[ "$auto_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "No fixture IPv4 address" >&2; exit 1; }
AMNEZIA_SSH_PROBE_HOST="$auto_ip"
export AMNEZIA_SSH_PROBE_NETWORK="$network" AMNEZIA_SSH_PROBE_PORT=2222 AMNEZIA_SSH_PROBE_PHASE=present
export QT_QPA_PLATFORM=offscreen
timeout 90 "$@" realAdminProbeAddressRead
timeout 90 "$@" realAdminPeerIPv6Read
timeout 90 "$@" realAdminIPv6InvitationExport
docker exec "$fixture" docker exec amnezia-wireguard sh -ec 'a=$(printf DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD | base64 | wg pubkey); wg set wg0 peer "$a" allowed-ips fd77::/64'
docker exec "$fixture" docker exec amnezia-awg2 sh -ec 'a=$(printf DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD | base64 | wg pubkey); awg set awg0 peer "$a" allowed-ips fd88::/64'
export AMNEZIA_SSH_PROBE_PHASE=ambiguous
timeout 90 "$@" realAdminPeerIPv6Read
docker exec "$fixture" docker stop amnezia-wireguard amnezia-awg2 >/dev/null
export AMNEZIA_SSH_PROBE_PHASE=missing
timeout 90 "$@" realAdminProbeAddressRead
timeout 90 "$@" realAdminPeerIPv6Read
echo 'PASS: real SSH, native WireGuard/AWG peer IPv6 discovery, ambiguous-address rejection, old admin probe migration and missing-container failures'
