#!/usr/bin/env bash
# Only the disposable nested daemon's network namespace is entered.
set -euo pipefail
if [[ $# -eq 0 ]]; then echo 'Usage: proxy-ipv6-activation.sh QT_TEST_EXECUTABLE [runner arguments...]' >&2; exit 2; fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if ! docker image inspect amnezia-local-vpn-tests >/dev/null 2>&1; then
    docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
fi
docker build --network host -t amnezia-xray-ipv6:local "$repo/client/server_scripts/xray"
build_root=$(cd "$(dirname "$1")/../.." && pwd)
export AMNEZIA_PROXY_SERVICE="$build_root/service/server/AmneziaVPN-service"
export AMNEZIA_TUN2SOCKS="$build_root/service/server/tun2socks"
export AMNEZIA_PROXY_DATA_PROBE="$(realpath "$repo/routing-service-probe-build/routing-service-probe")"
: "${AMNEZIA_PROXY_QT_ROOT:?Set the Qt installation root for the compiled service}"
docker build --network host --build-arg BASE_UBUNTU_VERSION=24.04 -t amnezia-proxy-tun:local "$repo/scripts/routing/linux-service-ci"
python3 "$repo/server/ipv6/lab/test_proxy_activation.py" --report proxy-ipv6-activation.json \
    --tun-runner "$repo/scripts/local-tests/linux-proxy-tun-runner.sh" -- \
    sudo nsenter --target '{pid}' --net env QT_QPA_PLATFORM=offscreen \
    AMNEZIA_PROXY_IPV6_TEST=isolated-docker AMNEZIA_PROXY_IPV6_CONTAINER='{protocol}' \
    AMNEZIA_PROXY_IPV6_EXPECT='{expected}' "$@" realProxyServerIpv6Activation
