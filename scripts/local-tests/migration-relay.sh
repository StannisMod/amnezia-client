#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
python3 "$repo/client/tests/migration/relay_acceptance.py"
