#!/usr/bin/env bash
# Dependency download only; all network fault experiments run separately offline.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
docker run --rm --network host --cpus 6 \
 --mount "type=bind,source=$repo,target=/src,readonly" \
 --mount type=volume,source=amnezia-local-full-build,target=/cache,readonly \
 --mount type=volume,source=amnezia-connection-stability-integration,target=/integration \
 --mount type=volume,source=amnezia-connection-stability-go-cache,target=/stability-cache \
 --entrypoint /bin/bash amnezia-connection-stability-lab -ec '
  if [ ! -d /integration/modules ]; then cp -a /cache/go/modules /integration/modules; fi
  if [ ! -d /stability-cache/build-cache ]; then cp -a /cache/go/build-cache /stability-cache/build-cache; fi
  export GOMODCACHE=/integration/modules GOCACHE=/stability-cache/build-cache GOTOOLCHAIN=local
  cd /src/native/routing
  go mod download
  python3 internal/builddeps/verify.py --module . --output /integration/normal-source-provenance.json
 '
