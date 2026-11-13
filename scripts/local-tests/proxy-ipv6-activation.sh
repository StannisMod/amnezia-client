#!/usr/bin/env bash
# Only the disposable nested daemon's network namespace is entered.
set -euo pipefail
if [[ $# -eq 0 ]]; then echo 'Usage: proxy-ipv6-activation.sh QT_TEST_EXECUTABLE [runner arguments...]' >&2; exit 2; fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if ! docker image inspect amnezia-local-vpn-tests >/dev/null 2>&1; then
    docker build --network host -t amnezia-local-vpn-tests -f "$repo/scripts/local-tests/Dockerfile.vpn" "$repo/scripts/local-tests"
fi
docker build --network host -t amnezia-xray-ipv6:local "$repo/client/server_scripts/xray"
python3 "$repo/server/ipv6/lab/test_proxy_activation.py" --report proxy-ipv6-activation.json -- \
    sudo nsenter --target '{pid}' --net env QT_QPA_PLATFORM=offscreen \
    AMNEZIA_PROXY_IPV6_TEST=isolated-docker AMNEZIA_PROXY_IPV6_CONTAINER='{protocol}' \
    AMNEZIA_PROXY_IPV6_EXPECT='{expected}' "$@" realProxyServerIpv6Activation
