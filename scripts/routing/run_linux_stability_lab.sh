#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
mode=${1:-kernel}
case "$mode" in userspace|kernel|native|events);; *) echo 'Usage: run_linux_stability_lab.sh userspace|kernel|native|events [output-directory]' >&2; exit 2;; esac
output=${2:-$(mktemp -d /tmp/amnezia-stability-lab.XXXXXX)}
mkdir -p "$output"
output=$(cd "$output" && pwd)
privileges=()
if [[ "$mode" != userspace ]]; then privileges=(--privileged); fi
protocol=${STABILITY_PROTOCOL:-wireguard}
family=${STABILITY_FAMILY:-IPv4}
[[ "$protocol" == wireguard || "$protocol" == awg ]]
[[ "$family" == IPv4 || "$family" == IPv6 ]]
docker image inspect amnezia-connection-stability-lab >/dev/null
if [[ "$mode" != events ]]; then bash "$repo/scripts/routing/prepare_stability_lab_cache.sh"; fi
# No host networking, namespaces, D-Bus, Docker socket or writable source mount.
docker run --rm --network none "${privileges[@]}" --cpus 6 \
 --mount "type=bind,source=$repo,target=/src,readonly" \
 --mount "type=bind,source=$output,target=/output" \
 --mount type=volume,source=amnezia-local-full-build,target=/cache,readonly \
 --mount type=volume,source=amnezia-connection-stability-integration,target=/integration,readonly \
 --mount type=volume,source=amnezia-connection-stability-go-cache,target=/stability-cache \
 -e STABILITY_MODE="$mode" -e STABILITY_PROTOCOL="$protocol" -e STABILITY_FAMILY="$family" \
 -e AMNEZIA_STABILITY_UPLOAD="${STABILITY_UPLOAD:-0}" \
 -e AMNEZIA_STABILITY_NO_OUTAGES="${STABILITY_NO_OUTAGES:-0}" \
 -e AMNEZIA_STABILITY_IMPAIRMENT_SECONDS="${STABILITY_IMPAIRMENT_SECONDS:-0}" \
 -e AMNEZIA_STABILITY_PROFILE="${STABILITY_PROFILE:-loss}" \
 -e STABILITY_TCP_CANDIDATE="${STABILITY_TCP_CANDIDATE:-integrated}" \
 -e STABILITY_PROBE="${STABILITY_PROBE:-0}" \
 -e STABILITY_RACE="${STABILITY_RACE:-0}" -e STABILITY_COUNT="${STABILITY_COUNT:-1}" \
 -e AMNEZIA_STABILITY_LAB=isolated-container \
 --entrypoint /bin/bash amnezia-connection-stability-lab -ec '
 set -o pipefail
 { uname -srmo; ip -Version; NetworkManager --version; cat /proc/sys/net/ipv4/tcp_congestion_control; } > /output/environment.txt
 if [ "$STABILITY_MODE" = events ]; then
  cmake -S /src/scripts/routing/stability/network-events -B /tmp/events-build -G Ninja >/output/build.log 2>&1
  cmake --build /tmp/events-build >>/output/build.log 2>&1
  cp /tmp/events-build/network-events /output/
  ip -ts monitor all > /output/netlink.log & monitor=$!
  trap "kill $monitor 2>/dev/null || true" EXIT
  python3 /src/scripts/routing/stability/network_events.py /output | tee /output/run.log
  exit
 fi
 if [ ! -d /stability-cache/build-cache ]; then cp -a /cache/go/build-cache /stability-cache/build-cache; fi
 export GOMODCACHE=/integration/modules GOCACHE=/stability-cache/build-cache GOPROXY=off GOTOOLCHAIN=local
 export AMNEZIA_STABILITY_REPRO=1 AMNEZIA_STABILITY_SEQUENCE=1 AMNEZIA_STABILITY_TRACE=/output
 cd /src/native/routing
 if [ "$STABILITY_TCP_CANDIDATE" != integrated ]; then
  python3 /src/scripts/routing/stability/prepare_tcp_candidates.py --output /output/tcp-candidate --candidate "$STABILITY_TCP_CANDIDATE" > /output/candidate.txt
  export GOFLAGS="-modfile=/output/tcp-candidate/$STABILITY_TCP_CANDIDATE.mod"
  sha256sum "/output/tcp-candidate/$STABILITY_TCP_CANDIDATE.patch" >> /output/environment.txt
 fi
 echo "TCP candidate: $STABILITY_TCP_CANDIDATE" >> /output/environment.txt
 tags=with_gvisor; if [ "$STABILITY_PROBE" = 1 ]; then tags=with_gvisor,stability_trace; fi
 if [ "$STABILITY_TCP_CANDIDATE" != integrated ]; then tags="$tags,amnezia_dependency_repro"; fi
 race=(); if [ "$STABILITY_RACE" = 1 ]; then race=(-race); fi
 if [ "$STABILITY_MODE" = userspace ]; then export AMNEZIA_STABILITY_USERSPACE_TRACE=1
 else export AMNEZIA_STABILITY_KERNEL_PEER=1; fi
 if [ "$STABILITY_MODE" = native ]; then
  go build -mod=readonly -tags "$tags" "${race[@]}" -o /output/amnezia-routing ./cmd/amnezia-routing
  export AMNEZIA_STABILITY_HELPER=/output/amnezia-routing
 fi
 ip -ts monitor all > /output/netlink.log & monitor=$!
 trap "kill $monitor 2>/dev/null || true" EXIT
 protocol=amnezia-wireguard; if [ "$STABILITY_PROTOCOL" = awg ]; then protocol=amneziawg; fi
 go test -mod=readonly -tags "$tags" "${race[@]}" -run "^TestConnectionStabilityReproduction$/^${protocol}$/^${STABILITY_FAMILY}$/" \
  -count "$STABILITY_COUNT" -timeout 12m -v ./engine 2>&1 | tee /output/run.log
 '
printf 'Artifacts: %s\n' "$output"
