# Included after the startup script's shebang; changes only this container's
# network namespace. The existing host/Docker firewall remains Docker-owned.
amnezia_ipv6_rule() {
    amnezia_v6_table=$1; shift
    ip6tables -t "$amnezia_v6_table" -C "$@" 2>/dev/null || ip6tables -t "$amnezia_v6_table" -A "$@"
}
amnezia_enable_ipv6() {
    amnezia_v6_tunnel=$1
    case "$amnezia_v6_tunnel" in wg0|awg0|tun0) ;; *) return 1 ;; esac
    amnezia_v6_addresses=$(ip -o -6 addr show dev "$amnezia_v6_tunnel" scope global) || return 1
    amnezia_v6_prefixes=$(printf '%s\n' "$amnezia_v6_addresses" | awk '{print $4}')
    if [ -z "$amnezia_v6_prefixes" ]; then
        if [ "${2:-}" = required ]; then
            echo 'AMNEZIA_IPV6_FORWARDING_STATUS=no-tunnel-address' >&2
            return 1
        fi
        return 0
    fi
    amnezia_v6_default=$(ip -6 route show default) || return 1
    amnezia_v6_egress=$(printf '%s\n' "$amnezia_v6_default" | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
    if [ -z "$amnezia_v6_egress" ] || [ "$amnezia_v6_egress" = "$amnezia_v6_tunnel" ]; then
        # OpenVPN may allocate an inner IPv6 address on an IPv4-only server.
        # Let the kernel return ICMPv6 no-route instead of silently dropping it.
        if [ "$amnezia_v6_tunnel" = tun0 ]; then
            sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || return 1
            amnezia_ipv6_rule filter INPUT -i tun0 -j ACCEPT || return 1
            amnezia_ipv6_rule filter OUTPUT -o tun0 -j ACCEPT || return 1
        fi
        echo 'AMNEZIA_IPV6_FORWARDING_STATUS=no-egress-route' >&2
        return 1
    fi
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || return 1
    amnezia_ipv6_rule filter INPUT -i "$amnezia_v6_tunnel" -j ACCEPT || return 1
    amnezia_ipv6_rule filter INPUT -i "$amnezia_v6_egress" -p ipv6-icmp -j ACCEPT || return 1
    amnezia_ipv6_rule filter OUTPUT -o "$amnezia_v6_tunnel" -j ACCEPT || return 1
    for amnezia_v6_prefix in $amnezia_v6_prefixes; do
        amnezia_ipv6_rule filter FORWARD -i "$amnezia_v6_tunnel" -o "$amnezia_v6_egress" -s "$amnezia_v6_prefix" -j ACCEPT || return 1
        amnezia_ipv6_rule filter FORWARD -i "$amnezia_v6_egress" -o "$amnezia_v6_tunnel" -d "$amnezia_v6_prefix" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
        amnezia_ipv6_rule filter FORWARD -i "$amnezia_v6_egress" -o "$amnezia_v6_tunnel" -d "$amnezia_v6_prefix" -p ipv6-icmp -j ACCEPT || return 1
        amnezia_ipv6_rule nat POSTROUTING -s "$amnezia_v6_prefix" -o "$amnezia_v6_egress" -j MASQUERADE || return 1
    done
    echo 'AMNEZIA_IPV6_FORWARDING_STATUS=routes-prepared-egress-unverified'
}

# The packaged startup script can prepare live IPv6 forwarding without running
# its tunnel teardown/startup body. Missing prerequisites are errors in this mode.
if [ "${1:-}" = --amnezia-prepare-ipv6-forwarding ]; then
    [ "$#" -eq 2 ] || exit 64
    amnezia_enable_ipv6 "$2" required || exit 1
    exit 0
fi
