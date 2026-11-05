#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if ! docker image inspect amnezia-local-vpn-tests >/dev/null 2>&1; then
    docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
fi
python3 "$repo/client/tests/migration/scenario_acceptance.py"
