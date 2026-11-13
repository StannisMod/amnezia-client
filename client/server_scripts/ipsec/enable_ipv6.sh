# Loaded only inside the dedicated IPsec container. Policy-based IPsec has no
# TUN device: constrain forwarding by XFRM policy and the managed address pool.
amnezia_ipsec_v6_rule() {
    amnezia_ipsec_table=$1; shift
    ip6tables -t "$amnezia_ipsec_table" -C "$@" 2>/dev/null || ip6tables -t "$amnezia_ipsec_table" -A "$@"
}
amnezia_ipsec_prepare_ipv6() {
    IPSEC_IKEV2_SUBNETS='0.0.0.0/0'
    IPSEC_IKEV2_POOL='192.168.43.10-192.168.43.250'
    # Updating settings on an old image must not feed unsupported pools to it.
    amnezia_ipsec_major=$(ipsec --version | sed -n 's/.*Libreswan \([0-9][0-9]*\)\..*/\1/p')
    case "$amnezia_ipsec_major" in ''|*[!0-9]*) return 1 ;; esac
    if [ "$amnezia_ipsec_major" -lt 5 ]; then
        echo 'AMNEZIA_IPSEC_IPV6_STATUS=requires-runtime-upgrade'
        return 0
    fi
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.all.forwarding=1 >/dev/null || return 1
    # Keep a valid source for ICMP errors, but do not route the whole client pool
    # to loopback: forwarded replies would become local input before XFRM.
    if ! ip -6 addr show dev lo | grep -Fq 'fd6e:a81b:704f:1201::1/128'; then
        ip -6 addr add fd6e:a81b:704f:1201::1/128 dev lo nodad || return 1
    fi
    amnezia_ipsec_pool='fd6e:a81b:704f:1201::/64'
    amnezia_ipsec_anchor=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    [ -n "$amnezia_ipsec_anchor" ] || amnezia_ipsec_anchor=$(ip -6 route show default | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    [ -n "$amnezia_ipsec_anchor" ] || return 1
    amnezia_ipsec_route=$(ip -6 route show exact "$amnezia_ipsec_pool") || return 1
    if [ -z "$amnezia_ipsec_route" ]; then
        ip -6 route add "$amnezia_ipsec_pool" dev "$amnezia_ipsec_anchor" proto static metric 42760 || return 1
    else
        printf '%s\n' "$amnezia_ipsec_route" | grep -Fq "dev $amnezia_ipsec_anchor proto static metric 42760" || return 1
    fi
    amnezia_ipsec_v6_rule filter INPUT -s "$amnezia_ipsec_pool" -m policy --dir in --pol ipsec -j ACCEPT || return 1
    amnezia_ipsec_v6_rule filter INPUT -s "$amnezia_ipsec_pool" -m policy --dir in --pol none -j DROP || return 1
    amnezia_ipsec_v6_rule filter INPUT -d "$amnezia_ipsec_pool" -m policy --dir in --pol none -j DROP || return 1
    amnezia_ipsec_v6_rule filter OUTPUT -d "$amnezia_ipsec_pool" -m policy --dir out --pol ipsec -j ACCEPT || return 1
    amnezia_ipsec_v6_rule filter OUTPUT -d "$amnezia_ipsec_pool" -m policy --dir out --pol none -j DROP || return 1
    amnezia_ipsec_v6_rule filter FORWARD -s "$amnezia_ipsec_pool" -m policy --dir in --pol ipsec -j ACCEPT || return 1
    amnezia_ipsec_v6_rule filter FORWARD -d "$amnezia_ipsec_pool" -m policy --dir out --pol ipsec -j ACCEPT || return 1
    amnezia_ipsec_v6_rule filter FORWARD -s "$amnezia_ipsec_pool" -m policy --dir in --pol none -j DROP || return 1
    amnezia_ipsec_v6_rule filter FORWARD -d "$amnezia_ipsec_pool" -m policy --dir out --pol none -j DROP || return 1
    amnezia_ipsec_egress=$(ip -6 route show default | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    if [ -n "$amnezia_ipsec_egress" ]; then
        amnezia_ipsec_v6_rule nat POSTROUTING -s "$amnezia_ipsec_pool" -o "$amnezia_ipsec_egress" -m policy --dir out --pol none -j MASQUERADE || return 1
        echo 'AMNEZIA_IPSEC_IPV6_STATUS=prepared-egress-unverified'
    else
        echo 'AMNEZIA_IPSEC_IPV6_STATUS=no-egress'
    fi
    IPSEC_IKEV2_SUBNETS='0.0.0.0/0,::/0'
    IPSEC_IKEV2_POOL='192.168.43.10-192.168.43.250,fd6e:a81b:704f:1201::1000-fd6e:a81b:704f:1201::1fff'
}
