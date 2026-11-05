#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if ! docker image inspect amnezia-local-qt-tests >/dev/null 2>&1; then
    docker build --network host -t amnezia-local-qt-tests -f "$repo/scripts/local-tests/Dockerfile.qt" "$repo/scripts/local-tests"
fi
docker build --network host -t amnezia-migration-ssh-tests -f "$repo/scripts/local-tests/Dockerfile.migration-ssh" "$repo/scripts/local-tests"
docker run --rm --network none --mount "type=bind,source=$repo,target=/src,readonly" \
    amnezia-migration-ssh-tests sh -ec 'cmake -S /src/client/tests/migration -B /tmp/migration-tests -G Ninja; cmake --build /tmp/migration-tests -j 4; python3 /src/client/tests/migration/ssh_acceptance.py'
