#!/bin/bash
# The image is inert: restore existing daemons after a container restart without
# executing the installer or replacing the persisted NSS identities.
amnezia_ipsec_prepare_ipv6 || exit 1
if [ -f /etc/ipsec.conf ]; then
    if ! pidof pluto >/dev/null; then
        amnezia_ipsec_migrate_ipv6_config /etc/ipsec.d/ikev2.conf || exit 1
        mkdir -p /run/pluto
        ipsec pluto --config /etc/ipsec.conf || exit 1
        ipsec addconn --autoall --config /etc/ipsec.conf
    fi
    if [ -f /etc/xl2tpd/xl2tpd.conf ] && ! pidof xl2tpd >/dev/null; then
        mkdir -p /var/run/xl2tpd
        /usr/sbin/xl2tpd -c /etc/xl2tpd/xl2tpd.conf
    fi
fi
