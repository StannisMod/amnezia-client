#!/usr/bin/env bash
# VPN tests get their own daemon/network/filesystem. Never mount the host socket
# inside the test container: acceptance uses names/ports from real deployments.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
suite=${1:-all}
case "$suite" in all|qt|vpn|wireguard|awg|awg2|ipsec) ;; *) echo 'Usage: run.sh [all|qt|vpn|wireguard|awg|awg2|ipsec] [--rebuild]' >&2; exit 2 ;; esac
image_options=()
case "${2:-}" in "") ;; --rebuild) image_options+=(--rebuild) ;; *) echo 'Only --rebuild is accepted as second argument' >&2; exit 2 ;; esac
ensure_image() {
    python3 "$repo/scripts/local-tests/lab_cache.py" image "$1" \
        --dockerfile "$repo/scripts/local-tests/$2" --context "$repo/scripts/local-tests" "${image_options[@]}"
}
docker info >/dev/null
runner=''
cleanup() {
    if [[ -n "$runner" ]]; then
        docker rm -f -v "$runner" >/dev/null
    fi
}
trap cleanup EXIT
if [[ "$suite" == all || "$suite" == qt ]]; then
    ensure_image amnezia-local-qt-tests Dockerfile.qt
    docker run --rm --pull=never --cpus 2 --memory 4g --memory-swap 4g \
        --mount "type=bind,source=$repo,target=/src,readonly" amnezia-local-qt-tests \
        sh -ec 'python3 client/tests/protocol-update/test_transaction.py; cmake -S client/tests/endpoints -B /tmp/endpoints -G Ninja; cmake --build /tmp/endpoints -j 2; ctest --test-dir /tmp/endpoints --output-on-failure; cmake -S client/tests/routing -B /tmp/routing -G Ninja; cmake --build /tmp/routing -j 2; ctest --test-dir /tmp/routing --output-on-failure'
fi
if [[ "$suite" != qt ]]; then
    ensure_image amnezia-local-vpn-tests Dockerfile.vpn
    protocols=(wireguard awg awg2-basic awg2-ranges ipsec)
    [[ "$suite" == wireguard || "$suite" == awg ]] && protocols=("$suite")
    [[ "$suite" == awg2 ]] && protocols=(awg2-basic awg2-ranges)
    [[ "$suite" == ipsec ]] && protocols=(ipsec)
    for protocol in "${protocols[@]}"; do
        runner="amnezia-local-$protocol-$(date +%s)-$RANDOM"
        docker run -d --pull=never --privileged --cpus 2 --memory 4g --memory-swap 4g --name "$runner" \
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
        protocol_args=(--kind "$protocol")
        if [[ "$protocol" == awg2-* ]]; then
            protocol_args=(--kind awg2 --legacy-profile "${protocol#awg2-}")
        fi
        if [[ "$protocol" == ipsec ]]; then
            docker exec "$runner" docker pull amneziavpn/ipsec-server@sha256:080673496751055c76389c76d87329f033ad7b514f52a776651617ba14179540
            docker exec "$runner" python3 /src/server/ipv6/lab/test_ipsec_update.py
        else
            docker exec "$runner" python3 /src/client/tests/protocol-update/acceptance.py "${protocol_args[@]}"
        fi
        cleanup
        runner=''
    done
fi
