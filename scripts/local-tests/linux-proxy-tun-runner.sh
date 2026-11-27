#!/usr/bin/env bash
# Called only for the owned Docker fixture created by test_proxy_activation.py.
set -euo pipefail
[[ $# == 2 ]]
[[ $(docker inspect -f '{{index .Config.Labels "amnezia.test-environment"}} {{.HostConfig.NetworkMode}}' "$1") == 'disposable none' ]]
: "${AMNEZIA_PROXY_SERVICE:?}" "${AMNEZIA_PROXY_DATA_PROBE:?}" "${AMNEZIA_TUN2SOCKS:?}" "${AMNEZIA_PROXY_QT_ROOT:?}"
mounts=()
declare -A mounted=()
mount_dir() {
    local directory
    directory=$(realpath "$1")
    if [[ -z ${mounted[$directory]:-} ]]; then
        mounted[$directory]=1
        mounts+=(-v "$directory:$directory:ro")
    fi
}
for binary in "$AMNEZIA_PROXY_SERVICE" "$AMNEZIA_PROXY_DATA_PROBE" "$AMNEZIA_TUN2SOCKS"; do
    mount_dir "$(dirname "$binary")"
    mount_dir "$(dirname "$(realpath "$binary")")"
done
mount_dir "$AMNEZIA_PROXY_QT_ROOT"
library_dirs=$(python3 - "$AMNEZIA_PROXY_SERVICE" "$AMNEZIA_PROXY_DATA_PROBE" <<'PY'
import re, subprocess, sys
from pathlib import Path
directories=set()
for binary in sys.argv[1:]:
    output=subprocess.check_output(['ldd',binary],text=True)
    if 'not found' in output: raise SystemExit(output)
    for line in output.splitlines():
        match=re.search(r'(?:=>\s+|^\s*)(/.*?)\s+\(0x[0-9a-fA-F]+\)',line)
        if not match: continue
        path=match.group(1)
        if not path.startswith(('/lib/','/lib64/','/usr/')): directories.add(str(Path(path).parent))
print('\n'.join(sorted(directories)))
PY
)
while IFS= read -r directory; do [[ -z "$directory" ]] || mount_dir "$directory"; done <<< "$library_dirs"
docker run --rm -i --privileged --network "container:$1" "${mounts[@]}" \
    -e QT_QPA_PLATFORM=offscreen -e LANG=C.UTF-8 \
    -e "QT_PLUGIN_PATH=$AMNEZIA_PROXY_QT_ROOT/plugins" \
    -e "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-$AMNEZIA_PROXY_QT_ROOT/lib}" \
    -e AMNEZIA_PROXY_ROUTE_TEST=isolated-docker -e "AMNEZIA_PROXY_SERVER_SUBNET=$2" \
    -e AMNEZIA_PROXY_CLIENT_CONFIG=/tmp/proxy-client.json \
    -e AMNEZIA_PROXY_SERVICE -e AMNEZIA_PROXY_DATA_PROBE -e AMNEZIA_TUN2SOCKS \
    --entrypoint bash "${AMNEZIA_PROXY_TUN_IMAGE:-amnezia-proxy-tun:local}" -ec '
        cat > /tmp/proxy-client.json
        "$AMNEZIA_PROXY_SERVICE" --console > /tmp/proxy-service.log 2>&1 & service_pid=$!
        trap '\''kill "$service_pid" 2>/dev/null || true; cat /tmp/proxy-service.log'\'' EXIT
        "$AMNEZIA_PROXY_DATA_PROBE" proxy-ipv6-data
    '
