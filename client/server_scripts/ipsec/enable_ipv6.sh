# Loaded only inside the dedicated IPsec container. Policy-based IPsec has no
# TUN device: constrain forwarding by XFRM policy and the managed address pool.
amnezia_ipsec_v6_rule() {
    amnezia_ipsec_table=$1; shift
    ip6tables -t "$amnezia_ipsec_table" -C "$@" 2>/dev/null || ip6tables -t "$amnezia_ipsec_table" -A "$@"
}
amnezia_ipsec_dual_stack_policy() {
    IPSEC_IKEV2_SUBNETS='0.0.0.0/0,::/0'
    IPSEC_IKEV2_POOL='192.168.43.10-192.168.43.250,fd6e:a81b:704f:1201::1000-fd6e:a81b:704f:1201::1fff'
}
amnezia_ipsec_migrate_ipv6_config() {
    amnezia_ipsec_config=$1
    [ -f "$amnezia_ipsec_config" ] || return 0
    [ ! -L "$amnezia_ipsec_config" ] || return 1
    [ "$IPSEC_IKEV2_SUBNETS" != '0.0.0.0/0' ] || return 0
    amnezia_ipsec_candidate=$(mktemp "${amnezia_ipsec_config}.ipv6.XXXXXX") || return 1
    # Only the standard managed connection is migrated. Refuse conflicting or
    # custom selectors instead of broadening a manually restricted policy.
    amnezia_ipsec_result=0
    awk -v selectors="$IPSEC_IKEV2_SUBNETS" -v pool="$IPSEC_IKEV2_POOL" '
        {
            normalized=$0; sub(/#.*/, "", normalized)
            gsub(/^[ \t]+|[ \t]+$/, "", normalized)
            if (normalized ~ /^conn[ \t]+/) {
                name=normalized; sub(/^conn[ \t]+/, "", name)
                active=(name=="ikev2-cp"); if(active) connections++
            }
            if(active && normalized ~ /^(leftsubnet|rightaddresspool)[ \t]*=/) {
                key=normalized; sub(/[ \t]*=.*/, "", key)
                value=normalized; sub(/^[^=]*=[ \t]*/, "", value)
                if(key=="leftsubnet") {
                    left++; old="0.0.0.0/0"; desired=selectors
                } else {
                    right++; old="192.168.43.10-192.168.43.250"; desired=pool
                }
                if(value==old) {
                    position=index($0,value)
                    $0=substr($0,1,position-1) desired substr($0,position+length(value))
                    changed++
                } else if(value!=desired) bad=1
            }
            print
        }
        END {
            if(bad || connections!=1 || left!=1 || right!=1) exit 1
            if(!changed) exit 2
        }' "$amnezia_ipsec_config" > "$amnezia_ipsec_candidate" || amnezia_ipsec_result=$?
    case "$amnezia_ipsec_result" in
        0)
            # Preserve ownership/mode and replace only after the entire file
            # passed validation. NSS files and client certificates are untouched.
            amnezia_ipsec_preserved=$(mktemp "${amnezia_ipsec_config}.metadata.XXXXXX") || { rm -f "$amnezia_ipsec_candidate"; return 1; }
            if cp -p "$amnezia_ipsec_config" "$amnezia_ipsec_preserved" &&
                cat "$amnezia_ipsec_candidate" > "$amnezia_ipsec_preserved" &&
                mv -f "$amnezia_ipsec_preserved" "$amnezia_ipsec_config"; then
                rm -f "$amnezia_ipsec_candidate"; return 0
            fi
            rm -f "$amnezia_ipsec_preserved"
            ;;
        2) rm -f "$amnezia_ipsec_candidate"; return 0 ;;
    esac
    rm -f "$amnezia_ipsec_candidate"
    return 1
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
    amnezia_ipsec_dual_stack_policy
}
