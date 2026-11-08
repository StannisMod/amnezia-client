#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
mode=${1:-matrix}
if [[ "$mode" != matrix && "$mode" != sequence ]]; then
    echo 'Usage: run_connection_stability_reproduction.sh [matrix|sequence]' >&2
    exit 2
fi
# Uses the existing local-test toolchain and dependency cache read-only. A
# separate cache is used here; no source copy or cache of another task is edited.
docker image inspect amnezia-local-full-build >/dev/null
docker volume inspect amnezia-local-full-build >/dev/null
bash "$repo/scripts/routing/prepare_stability_lab_cache.sh"
docker run --rm --network none --cpus 6 \
    --mount "type=bind,source=$repo,target=/src,readonly" \
    --mount type=volume,source=amnezia-local-full-build,target=/cache,readonly \
    --mount type=volume,source=amnezia-connection-stability-integration,target=/integration,readonly \
    --mount type=volume,source=amnezia-connection-stability-go-cache,target=/stability-cache \
    -e STABILITY_MODE="$mode" \
    --entrypoint /bin/bash amnezia-connection-stability-lab -ec '
        if [ ! -d /stability-cache/build-cache ]; then
            cp -a /cache/go/build-cache /stability-cache/build-cache
        fi
        export GOMODCACHE=/integration/modules GOCACHE=/stability-cache/build-cache
        export GOPROXY=off GOTOOLCHAIN=local AMNEZIA_STABILITY_REPRO=1
        cd /src/native/routing
        if [ "$STABILITY_MODE" = sequence ]; then
            export AMNEZIA_STABILITY_SEQUENCE=1
        fi
        go test -mod=readonly -tags with_gvisor -race -count=1 -v ./awg ./wireguard
        go test -mod=readonly -tags with_gvisor -parallel 16 -count=1 \
            -run TestConnectionStabilityReproduction -timeout 6m -v ./engine
    '
