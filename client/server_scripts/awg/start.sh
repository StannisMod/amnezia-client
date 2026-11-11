#!/bin/bash

# This scripts copied from Amnezia client to Docker container to /opt/amnezia and launched every time container starts

echo "Container startup"
#ifconfig eth0:0 $SERVER_IP_ADDRESS netmask 255.255.255.255 up

# Stop the route owner before restarting the tunnel.
if [ -f /run/amnezia-mtu.pid ]; then
    mtu_old=$(cat /run/amnezia-mtu.pid)
    if [ -r "/proc/$mtu_old/cmdline" ] && grep -aq 'supervisor.py' "/proc/$mtu_old/cmdline"; then
        kill -TERM "$mtu_old"
        for attempt in $(seq 1 50); do
            kill -0 "$mtu_old" 2>/dev/null || break
            sleep 0.2
        done
    fi
fi

# kill daemons in case of restart
awg-quick down /opt/amnezia/awg/awg0.conf

# start daemons if configured
if [ -f /opt/amnezia/awg/awg0.conf ]; then (awg-quick up /opt/amnezia/awg/awg0.conf); fi

amnezia_enable_ipv6 awg0 || exit 1

# Allow traffic on the TUN interface.
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT

# Allow forwarding traffic only from the VPN.
iptables -A FORWARD -i awg0 -o eth0 -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -j ACCEPT
iptables -A FORWARD -i awg0 -o eth1 -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $AWG_SUBNET_IP/$WIREGUARD_SUBNET_CIDR -o eth1 -j MASQUERADE

# The supervisor restores its owned peer route metrics on termination.
python3 /opt/amnezia/mtu/current/supervisor.py --interface awg0 --command awg &
mtu_pid=$!
echo "$mtu_pid" > /run/amnezia-mtu.pid
trap 'kill -TERM "$mtu_pid" 2>/dev/null; wait "$mtu_pid"' TERM INT EXIT
wait "$mtu_pid"
