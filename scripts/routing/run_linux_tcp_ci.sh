#!/usr/bin/env bash
# Native TCP-preservation gate confined to disposable mount/network namespaces.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${RUNNER_TEMP:?Set the private CI artifact directory}"
output="$RUNNER_TEMP/tcp-stability"
mkdir -p "$output"
copy_tcp_artifacts() {
  local target="$repo/tcp-stability-artifacts"
  mkdir -p "$target"
  for file in "$output/"*.json "$output/"*.log; do
    if [ -f "$file" ]; then cp "$file" "$target/"; fi
  done
  for direction in download upload; do
    if [ -d "$output/$direction" ]; then cp -R "$output/$direction" "$target/"; fi
  done
}
trap 'tcp_status=$?; copy_tcp_artifacts; exit "$tcp_status"' EXIT
cd "$repo/native/routing"
export GOTOOLCHAIN=local GOPROXY=off
go build -mod=readonly -trimpath -buildvcs=false -tags with_gvisor -o "$output/amnezia-routing" ./cmd/amnezia-routing
python3 internal/builddeps/verify.py --module . --binary "$output/amnezia-routing" --output "$output/tcp-dependency.json"
go test -mod=readonly -tags with_gvisor -c -o "$output/engine.test" ./engine
privilege=()
if [ "$(id -u)" != 0 ]; then privilege=(sudo); fi
for direction in download upload; do
  upload=0; if [ "$direction" = upload ]; then upload=1; fi
  mkdir -p "$output/$direction"
  "${privilege[@]}" env AMNEZIA_STABILITY_REPRO=1 AMNEZIA_STABILITY_SEQUENCE=1 \
    AMNEZIA_STABILITY_KERNEL_PEER=1 AMNEZIA_STABILITY_LAB=isolated-namespace \
    AMNEZIA_STABILITY_HELPER="$output/amnezia-routing" AMNEZIA_STABILITY_UPLOAD="$upload" \
    AMNEZIA_STABILITY_TRACE="$output/$direction" \
    unshare --mount --net --fork bash -ec '
      mount --make-rprivate /
      ip link set lo up
      mkdir -p /run/netns
      mount -t tmpfs tmpfs /run/netns
      "$1" -test.run "^TestConnectionStabilityReproduction$" -test.count 1 -test.timeout 10m -test.v
    ' _ "$output/engine.test" 2>&1 | tee "$output/$direction.log"
done
