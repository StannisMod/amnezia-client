# Prepare a separate IPv6-only bridge for AWG/WG. Never recreate the existing
# DNS bridge or change the Docker daemon's global networking configuration.
AMNEZIA_IPV6_NETWORK=''
amnezia_prepare_ipv6_network() {
    if ! ip -6 route show default 2>/dev/null | grep -q '^default'; then
        echo 'AMNEZIA_IPV6_NETWORK_STATUS=no-host-default-route'
        return 0
    fi
    if ! sudo docker network create --help | grep -q -- '--ipv4'; then
        echo 'AMNEZIA_IPV6_NETWORK_STATUS=ipv6-only-bridge-unsupported'
        return 0
    fi
    amnezia_v6_name='amnezia-ipv6-egress'
    if sudo docker network inspect "$amnezia_v6_name" >/dev/null 2>&1; then
        amnezia_v6_shape=$(sudo docker network inspect --format '{{.Driver}} {{.EnableIPv6}} {{.EnableIPv4}} {{index .Labels "com.amnezia.ipv6-egress"}}' "$amnezia_v6_name") || return 1
        if [ "$amnezia_v6_shape" != 'bridge true false v1' ]; then
            echo 'AMNEZIA_IPV6_NETWORK_STATUS=existing-network-conflict' >&2
            return 1
        fi
    else
        amnezia_v6_random=$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')
        amnezia_v6_prefix=$(printf '%s' "$amnezia_v6_random" | sed -E 's/^(..)(....)(....)$/fd\1:\2:\3:0::\/64/')
        case "$amnezia_v6_prefix" in fd*::*\/64) ;; *) return 1 ;; esac
        if ! sudo docker network create --driver bridge --ipv4=false --ipv6 \
            --subnet "$amnezia_v6_prefix" --label com.amnezia.ipv6-egress=v1 \
            --opt com.docker.network.bridge.name=amn6 "$amnezia_v6_name" >/dev/null; then
            echo 'AMNEZIA_IPV6_NETWORK_STATUS=create-failed' >&2
            return 1
        fi
    fi
    AMNEZIA_IPV6_NETWORK="$amnezia_v6_name"
    echo 'AMNEZIA_IPV6_NETWORK_STATUS=bridge-prepared-egress-unverified'
}
amnezia_prepare_ipv6_network || exit 1
