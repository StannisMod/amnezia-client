mkdir -p /opt/amnezia/wireguard
cd /opt/amnezia/wireguard
WIREGUARD_SERVER_PRIVATE_KEY=$(wg genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/wireguard/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | wg pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/wireguard/wireguard_server_public_key.key

WIREGUARD_PSK=$(wg genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/wireguard/wireguard_psk.key

# Keep already configured IPv6 addresses, but do not advertise a newly attached
# bridge as working Internet egress. Fresh IPv6 is added by the live coordinator
# after startup and an authenticated source-bound reachability check.
AMNEZIA_TUN_IPV6_SUFFIX=''
if [ -f /opt/amnezia/wireguard/wg0.conf ]; then
    AMNEZIA_TUN_IPV6_SUFFIX=$(awk '
        { sub(/#.*/, "") }
        /^[[:space:]]*\[/ { section=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", section) }
        section=="[Interface]" && /^[[:space:]]*Address[[:space:]]*=/ {
            sub(/^[^=]*=/, ""); n=split($0, addresses, ",")
            for(i=1;i<=n;i++) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", addresses[i])
                if(index(addresses[i], ":")) printf ", %s", addresses[i]
            }
        }' /opt/amnezia/wireguard/wg0.conf)
fi

cat > /opt/amnezia/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = $WIREGUARD_SUBNET_IP/$WIREGUARD_SUBNET_CIDR$AMNEZIA_TUN_IPV6_SUFFIX
ListenPort = $WIREGUARD_SERVER_PORT
EOF
