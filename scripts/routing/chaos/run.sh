#!/usr/bin/env bash
set -euo pipefail
lab=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$lab/../../.." && pwd)
image=${CHAOS_IMAGE:-amnezia-linux-tcp-chaos:local}
output=${CHAOS_OUTPUT:-$PWD/chaos-results/$(date -u +%Y%m%dT%H%M%SZ)}
if [[ "${1:-}" == --build ]]; then
 shift
 docker build -f "$lab/Dockerfile" -t "$image" "$repo"
fi
mkdir -p "$output"
output=$(cd "$output" && pwd)
# The container has no uplink, host namespace, Docker socket, host /run, /sys
# mount. Privilege is required for TUN, netns mounts and TUN-local sysctls.
docker run --rm --init --network none --privileged --pids-limit 512 --memory 3g --cpus 4 \
 --mount "type=bind,source=$output,target=/results" "$image" "$@"
echo "Report: $output/report.json"
