#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
output=${1:-$(mktemp -d /tmp/amnezia-tcp-comparison.XXXXXX)}
mkdir -p "$output"
output=$(cd "$output" && pwd)
bash "$repo/scripts/routing/prepare_stability_lab_cache.sh"
docker run --rm --network none --cpus 6 \
 --mount "type=bind,source=$repo,target=/src,readonly" \
 --mount "type=bind,source=$output,target=/output" \
 --mount type=volume,source=amnezia-local-full-build,target=/cache,readonly \
 --mount type=volume,source=amnezia-connection-stability-integration,target=/integration,readonly \
 --mount type=volume,source=amnezia-connection-stability-go-cache,target=/stability-cache \
 --entrypoint /bin/bash amnezia-connection-stability-lab -ec '
 export GOMODCACHE=/integration/modules GOCACHE=/stability-cache/build-cache GOPROXY=off GOTOOLCHAIN=local AMNEZIA_TCP_RECOVERY_REPRO=1
 cd /src/native/routing
 python3 /src/scripts/routing/stability/prepare_tcp_candidates.py --output /output/candidates > /output/modfiles.txt
 for candidate in stock guard pipe combined; do
  set +e
  go test -mod=readonly -modfile=/output/candidates/$candidate.mod -tags with_gvisor,amnezia_dependency_repro \
    -run TestTCPTimeoutRecoveryDrainsThroughACKs -count=1 -timeout 30s -v ./awg > /output/$candidate.log 2>&1
  result=$?
  set -e
  printf "%s %s\n" "$candidate" "$result" >> /output/results.txt
  if [ "$candidate" = pipe ]; then [ "$result" = 0 ]; else [ "$result" != 0 ]; fi
 done
 go test -mod=readonly -modfile=/output/candidates/pipe.mod -tags with_gvisor,amnezia_dependency_repro -race \
   -run TestTCPTimeoutRecoveryDrainsThroughACKs -count=100 -timeout 3m ./awg > /output/repeat-race.log 2>&1
 go test -mod=readonly -modfile=/output/candidates/pipe.mod -tags with_gvisor,stability_trace,amnezia_dependency_repro -race \
   -count=1 -timeout 3m ./... > /output/regression-race.log 2>&1
 go mod verify > /output/module-verification.txt
 cat /output/results.txt
 cat /output/repeat-race.log
 '
printf 'Artifacts: %s\n' "$output"
