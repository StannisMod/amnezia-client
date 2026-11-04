#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
runner="amnezia-connection-updates-test-$RANDOM-$(date +%s)"
cleanup() { docker rm -f -v "$runner" >/dev/null; }
trap cleanup EXIT
docker run -d --privileged --name "$runner" --dns 1.1.1.1 --dns 8.8.8.8 \
    --label amnezia.local-tests=true --mount "type=bind,source=$repo,target=/src,readonly" \
    -e DOCKER_TLS_CERTDIR= amnezia-local-vpn-tests --host=unix:///var/run/docker.sock \
    --dns=1.1.1.1 --dns=8.8.8.8 --label amnezia.test-environment=disposable >/dev/null
ready=false
for attempt in {1..60}; do
    if docker exec "$runner" docker info >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
if [[ "$ready" != true ]]; then docker logs "$runner"; exit 1; fi
docker exec "$runner" python3 /src/client/tests/connection-updates/acceptance.py
