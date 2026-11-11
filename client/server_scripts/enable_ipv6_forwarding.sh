# Included after the startup script's shebang; changes only this container's
# network namespace. The existing host/Docker firewall remains Docker-owned.
amnezia_ipv6_rule() {
    amnezia_v6_table=$1; shift
    ip6tables -t "$amnezia_v6_table" -C "$@" 2>/dev/null || ip6tables -t "$amnezia_v6_table" -A "$@"
}
amnezia_enable_ipv6() {
    amnezia_v6_tunnel=$1
    case "$amnezia_v6_tunnel" in wg0|awg0) ;; *) return 1 ;; esac
    amnezia_v6_prefixes=$(ip -o -6 addr show dev "$amnezia_v6_tunnel" scope global | awk '{print $4}') || return 1
    [ -n "$amnezia_v6_prefixes" ] || return 0
    amnezia_v6_egress=$(ip -6 route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
    if [ -z "$amnezia_v6_egress" ] || [ "$amnezia_v6_egress" = "$amnezia_v6_tunnel" ]; then
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
