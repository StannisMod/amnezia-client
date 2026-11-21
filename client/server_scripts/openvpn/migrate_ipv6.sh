# Included in OpenVPN startup. Only prepare the existing configuration before
# the daemon starts; never regenerate a CA, certificate, key or IPv4 pool.
amnezia_prepare_openvpn_ipv6() {
    amnezia_ovpn_config=$1
    [ -f "$amnezia_ovpn_config" ] && [ ! -L "$amnezia_ovpn_config" ] || return 1
    # Keep an explicit administrator-selected pool, including its formatting.
    if awk '$1 == "server-ipv6" || $1 == "--server-ipv6" { found=1 } END { exit !found }' "$amnezia_ovpn_config"; then
        return 0
    fi
    # This migration applies to managed IPv4 server configurations only.
    awk '$1 == "server" || $1 == "--server" { found=1 } END { exit !found }' "$amnezia_ovpn_config" || return 1
    [ -r /proc/sys/net/ipv6/conf/default/disable_ipv6 ] || return 1
    [ "$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)" = 0 ] || return 1
    amnezia_ovpn_candidate=$(mktemp "${amnezia_ovpn_config}.ipv6.XXXXXX") || return 1
    if cp -p "$amnezia_ovpn_config" "$amnezia_ovpn_candidate" &&
        printf '\n# Amnezia managed IPv6 pool; existing client identities are unchanged.\nserver-ipv6 fd6e:a81b:704f:1101::/64\n' >> "$amnezia_ovpn_candidate" &&
        mv -f "$amnezia_ovpn_candidate" "$amnezia_ovpn_config"; then
        return 0
    fi
    rm -f "$amnezia_ovpn_candidate"
    return 1
}
