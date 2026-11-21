#!/usr/bin/env bash
# All routes, TLS origins and VPN servers belong to a disposable nested daemon.
set -euo pipefail
if [[ $# -eq 0 ]]; then echo 'Usage: ipv6-activation.sh QT_TEST_EXECUTABLE [runner arguments...]' >&2; exit 2; fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if ! docker image inspect amnezia-local-vpn-tests >/dev/null 2>&1; then
    docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
fi
docker build --network host -t amnezia-ipv6-upgrade-helper:local "$repo/client/server_scripts/connection_updates"
builder_image=${AMNEZIA_IPV6_BUILDER_IMAGE:-golang:1.27.1}
# A BuildKit FROM cache is not an image tag that docker save can preload.
# Materialize the builder before entering the deliberately offline namespace.
if ! docker image inspect "$builder_image" >/dev/null 2>&1; then
    docker pull "$builder_image"
fi
python3 "$repo/server/ipv6/lab/test_activation.py" --builder-image "$builder_image" --report ipv6-activation.json -- \
    sudo nsenter --target '{pid}' --net env QT_QPA_PLATFORM=offscreen \
    AMNEZIA_IPV6_ACTIVATION_TEST=isolated-docker AMNEZIA_SSH_PROBE_HOST=127.0.0.1 \
    AMNEZIA_SSH_PROBE_PORT=2222 AMNEZIA_IPV6_CONTAINER='{protocol}' AMNEZIA_IPV6_EXPECT='{expected}' \
    "$@" realServerIPv6Activation
