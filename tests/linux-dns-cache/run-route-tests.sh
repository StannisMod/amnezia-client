#!/bin/bash
set -euo pipefail
ns="amnezia-routing-test-$$"
if ! ip netns add "$ns" 2>/dev/null; then
    echo 'Network-namespace routing tests require root and CAP_NET_ADMIN.'
    if [ "${AMNEZIA_REQUIRE_ROUTE_TESTS:-0}" = 1 ]; then exit 1; fi
    exit 77
fi
trap 'ip netns del "$ns"' EXIT
ip -n "$ns" link set lo up
for dev in amn0 uplink0 lan0; do
    ip -n "$ns" link add "$dev" type dummy
    ip -n "$ns" link set "$dev" up
done
ip -n "$ns" addr add 192.0.2.2/24 dev uplink0
ip -n "$ns" addr add 10.20.0.2/24 dev lan0
ip -n "$ns" addr add 10.8.0.2/24 dev amn0
ip -n "$ns" route add default via 192.0.2.1
ip -n "$ns" route add 198.51.100.42/32 via 10.20.0.1
ip -n "$ns" route add table 201 203.0.113.0/24 via 10.20.0.1 dev lan0
ip -n "$ns" rule add priority 32765 to 203.0.113.0/24 lookup 201
ip -n "$ns" route add blackhole 198.18.0.0/15 table 51820
ip -n "$ns" -6 addr add 2001:db8:1::2/64 dev uplink0 nodad
ip -n "$ns" -6 addr add 2001:db8:2::2/64 dev lan0 nodad
ip -n "$ns" -6 addr add fd58:baa6:dead::1/64 dev amn0 nodad
ip -n "$ns" -6 route add default via 2001:db8:1::1 dev uplink0
ip netns exec "$ns" "$1"
