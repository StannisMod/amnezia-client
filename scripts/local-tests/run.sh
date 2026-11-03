#!/usr/bin/env bash
# VPN tests get their own daemon/network/filesystem. Never mount the host socket
# inside the test container: acceptance uses names/ports from real deployments.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
suite=${1:-all}
case "$suite" in all|qt|vpn|wireguard|awg) ;; *) echo 'Usage: run.sh [all|qt|vpn|wireguard|awg]' >&2; exit 2 ;; esac
docker info >/dev/null
runner=''
cleanup() {
    if [[ -n "$runner" ]]; then
        docker rm -f -v "$runner" >/dev/null
    fi
}
trap cleanup EXIT
if [[ "$suite" == all || "$suite" == qt ]]; then
    docker build --network host -t amnezia-local-qt-tests -f "$repo/scripts/local-tests/Dockerfile.qt" "$repo/scripts/local-tests"
    docker run --rm --mount "type=bind,source=$repo,target=/src,readonly" amnezia-local-qt-tests \
        sh -ec 'python3 client/tests/protocol-update/test_transaction.py; cmake -S client/tests/endpoints -B /tmp/endpoints -G Ninja; cmake --build /tmp/endpoints -j 4; ctest --test-dir /tmp/endpoints --output-on-failure; cmake -S client/tests/routing -B /tmp/routing -G Ninja; cmake --build /tmp/routing -j 4; ctest --test-dir /tmp/routing --output-on-failure'
fi
if [[ "$suite" != qt ]]; then
    docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
    protocols=(wireguard awg)
    [[ "$suite" == wireguard || "$suite" == awg ]] && protocols=("$suite")
    for protocol in "${protocols[@]}"; do
        runner="amnezia-local-$protocol-$(date +%s)-$RANDOM"
        docker run -d --privileged --name "$runner" \
            --dns 1.1.1.1 --dns 8.8.8.8 \
            --label amnezia.local-tests=true \
            --mount "type=bind,source=$repo,target=/src,readonly" \
            --mount type=bind,source=/lib/modules,target=/lib/modules,readonly \
            -e DOCKER_TLS_CERTDIR= amnezia-local-vpn-tests \
            --host=unix:///var/run/docker.sock --dns=1.1.1.1 --dns=8.8.8.8 \
            --label amnezia.test-environment=disposable >/dev/null
        ready=false
        for attempt in {1..60}; do
            if docker exec "$runner" docker info >/dev/null 2>&1; then ready=true; break; fi
            sleep 1
        done
        if [[ "$ready" != true ]]; then docker logs "$runner"; exit 1; fi
        docker exec "$runner" python3 /src/client/tests/protocol-update/acceptance.py --kind "$protocol"
        cleanup
        runner=''
    done
fi
