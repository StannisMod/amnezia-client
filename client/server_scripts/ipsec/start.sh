#!/bin/bash
# amnezia-managed-ipsec-startup-v1
# The image is inert: restore existing daemons after a container restart without
# executing the installer or replacing the persisted NSS identities.
if ! pidof pluto >/dev/null; then
    if [ -f /opt/amnezia/ipsec-ipv4.rules ]; then
        iptables-restore < /opt/amnezia/ipsec-ipv4.rules || exit 1
    fi
    if [ -f /opt/amnezia/ipsec-ipv4.sysctl ]; then
        sysctl -p /opt/amnezia/ipsec-ipv4.sysctl >/dev/null || exit 1
    fi
fi
amnezia_ipsec_prepare_ipv6 || exit 1
if [ -f /etc/ipsec.conf ]; then
    if ! pidof pluto >/dev/null; then
        amnezia_ipsec_migrate_ipv6_config /etc/ipsec.d/ikev2.conf || exit 1
        mkdir -p /run/pluto
        # /run is not a tmpfs in the managed container. A Docker restart can
        # retain this lock file after its process has already been destroyed.
        rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid
        ipsec pluto --config /etc/ipsec.conf || exit 1
        ipsec addconn --autoall --config /etc/ipsec.conf
    fi
    if [ -f /etc/xl2tpd/xl2tpd.conf ] && ! pidof xl2tpd >/dev/null; then
        mkdir -p /var/run/xl2tpd
        /usr/sbin/xl2tpd -c /etc/xl2tpd/xl2tpd.conf
    fi
fi
echo 'AMNEZIA_IPSEC_STARTUP=completed'
exec tail -f /dev/null
