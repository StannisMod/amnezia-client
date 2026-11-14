#!/bin/sh
# Standard managed IPsec containers only. No issuer/configure script is run.
# Stage contains Dockerfile, composed start.sh, enable_ipv6.sh and network.sh.
set -eu
umask 077
[ "$1" = ipsec ] || exit 1
stage=$2
case "$stage" in /tmp/amnezia-update-*) ;; *) exit 1 ;; esac
id=${stage#/tmp/amnezia-update-}
case "$id" in ''|*[!a-f0-9-]*) exit 1 ;; esac
name=amnezia-ipsec
exec 3>&1
mkdir -p /var/lib/amnezia/updates
chmod 700 /var/lib/amnezia/updates
exec 9>"/var/lib/amnezia/updates/$name.lock"
if ! flock -n 9; then echo amnezia_update=busy >&3; exit 1; fi
work="/var/lib/amnezia/updates/$name-$id"
mkdir "$work"
exec >"$work/update.log" 2>&1
old="$name-backup-$id"
touched=0
committed=0
restart=always
legacy_startup=1
result=rejected

healthy() {
    attempt=0
    while [ "$attempt" -lt 15 ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$1")" = true ] &&
            docker exec "$1" pidof pluto >/dev/null 2>&1 &&
            docker exec "$1" ipsec auto --status | grep -q '"ikev2-cp"'; then return 0; fi
        attempt=$((attempt + 1)); sleep 1
    done
    return 1
}

identities() {
    docker exec "$1" bash -e -o pipefail -c '
        certutil -L -d sql:/etc/ipsec.d |
            awk '\''NR>4 && NF {gsub(/[[:space:]]+/," "); sub(/^ /,""); print}'\'' | LC_ALL=C sort
        certutil -K -d sql:/etc/ipsec.d 2>/dev/null |
            sed -n '\''s/^<[^>]*>[[:space:]]*//p'\'' | LC_ALL=C sort'
}

legacy_start() {
    # The original image's inert ENTRYPOINT cannot restore the old daemon by
    # itself. Use only its own configuration, without IPv6 migration or issuance.
    docker exec -i "$1" iptables-restore < "$work/ipv4.rules" || return 1
    docker cp "$work/ipv4.sysctl" "$1:/opt/amnezia/ipsec-ipv4.sysctl" || return 1
    docker exec "$1" sysctl -p /opt/amnezia/ipsec-ipv4.sysctl >/dev/null || return 1
    docker exec "$1" sh -ec '
        if ! pidof pluto >/dev/null; then
            mkdir -p /run/pluto
            rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid
            ipsec pluto --config /etc/ipsec.conf
            ipsec addconn --autoall --config /etc/ipsec.conf
        fi
        if [ -f /etc/xl2tpd/xl2tpd.conf ] && ! pidof xl2tpd >/dev/null; then
            mkdir -p /var/run/xl2tpd
            rm -f /var/run/xl2tpd.pid
            /usr/sbin/xl2tpd -c /etc/xl2tpd/xl2tpd.conf
        fi'
}

finish() {
    trap - EXIT HUP INT TERM
    if [ "$committed" = 0 ] && [ "$touched" = 1 ]; then
        result=rollback_failed
        restored=1
        current=$(docker inspect -f '{{.Id}}' "$name" 2>/dev/null) || current=''
        if [ -n "$current" ] && [ "$current" != "$original" ]; then
            owner=$(docker inspect -f '{{index .Config.Labels "amnezia.protocol-update"}}' "$current") || owner=''
            if [ "$owner" = "$id" ]; then docker rm -f "$current" || restored=0; else restored=0; fi
        fi
        original_name=$(docker inspect -f '{{.Name}}' "$original") || original_name=''
        if [ "$original_name" != "/$name" ]; then docker rename "$original" "$name" || restored=0; fi
        # Managed cold startup must restore the latest captured live policy too,
        # including administrator changes made since the previous cold boot.
        docker cp "$work/ipv4.rules" "$original:/opt/amnezia/ipsec-ipv4.rules" || restored=0
        docker cp "$work/ipv4.sysctl" "$original:/opt/amnezia/ipsec-ipv4.sysctl" || restored=0
        docker update --restart="$restart" "$original" || restored=0
        docker start "$original" || restored=0
        if [ "$legacy_startup" = 1 ]; then legacy_start "$original" || restored=0; fi
        if [ "$restored" = 1 ] && healthy "$original"; then result=rolled_back; fi
    fi
    printf '%s\n' "$result" > "$work/result"
    printf 'amnezia_update=%s\n' "$result" >&3
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

original=$(docker inspect -f '{{.Id}}' "$name")
healthy "$original"
case "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$original")" in bridge|default) ;; *) exit 1 ;; esac
[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$original")" = true ]
[ "$(docker inspect -f '{{.HostConfig.PidMode}}' "$original")" = '' ]
case "$(docker inspect -f '{{.Config.User}}' "$original")" in ''|root|0) ;; *) exit 1 ;; esac
[ "$(docker inspect -f '{{len .Mounts}}' "$original")" = 0 ]
# The transaction supports the application's standard deployment. Refuse
# custom host restrictions/resolver overrides instead of silently discarding
# them when the replacement is created.
for field in Dns DnsOptions DnsSearch ExtraHosts CapAdd CapDrop Devices DeviceRequests Binds Tmpfs Sysctls; do
    value=$(docker inspect -f "{{json (index .HostConfig \"$field\")}}" "$original")
    case "$value" in null|'[]'|'{}') ;; *) exit 1 ;; esac
done
# Docker adds label=disable automatically to privileged containers.
case "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$original")" in null|'[]'|'["label=disable"]') ;; *) exit 1 ;; esac
for field in Memory MemorySwap NanoCpus CpuQuota CpuPeriod CpuShares BlkioWeight; do
    [ "$(docker inspect -f "{{index .HostConfig \"$field\"}}" "$original")" = 0 ]
done
case "$(docker inspect -f '{{json .HostConfig.PidsLimit}}' "$original")" in null|0) ;; *) exit 1 ;; esac
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$original")" = false ]
[ "$(docker inspect -f '{{.HostConfig.PublishAllPorts}}' "$original")" = false ]
base_image=$(docker inspect -f '{{.Image}}' "$original")
[ "$(docker inspect -f '{{json .Config.Env}}' "$original")" = "$(docker image inspect -f '{{json .Config.Env}}' "$base_image")" ]
restart=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$original")
case "$restart" in always|unless-stopped|no) ;; *) exit 1 ;; esac
[ "$(docker inspect -f '{{len .HostConfig.PortBindings}}' "$original")" = 2 ]
for port in 500 4500; do
    [ "$(docker inspect -f "{{len (index .HostConfig.PortBindings \"$port/udp\")}}" "$original")" = 1 ]
    [ "$(docker inspect -f "{{(index (index .HostConfig.PortBindings \"$port/udp\") 0).HostPort}}" "$original")" = "$port" ]
    host=$(docker inspect -f "{{(index (index .HostConfig.PortBindings \"$port/udp\") 0).HostIp}}" "$original")
    case "$host" in '') binding="$port:$port/udp" ;; 0.0.0.0) binding="0.0.0.0:$port:$port/udp" ;; *) exit 1 ;; esac
    printf '%s\n' "$binding" > "$work/binding-$port"
done
docker inspect "$original" > "$work/original-container.json"
docker inspect -f '{{range $key, $value := .NetworkSettings.Networks}}{{println $key}}{{end}}' "$original" > "$work/networks"
while IFS= read -r network; do
    case "$network" in ''|bridge|amnezia-dns-net|amnezia-ipv6-egress) ;; *) exit 1 ;; esac
done < "$work/networks"
docker exec "$original" sh -ec '
    test -f /etc/ipsec.conf && test ! -L /etc/ipsec.conf
    test -d /etc/ipsec.d && test ! -L /etc/ipsec.d
    test -f /etc/ipsec.d/ikev2.conf && test ! -L /etc/ipsec.d/ikev2.conf
    if test -s /opt/amnezia/start.sh; then grep -q "^# amnezia-managed-ipsec-startup-v1$" /opt/amnezia/start.sh; fi'
case "$(docker inspect -f '{{json (index .Config "Entrypoint")}}' "$original")" in
    '["dumb-init","tail","-f","/dev/null"]') legacy_startup=1 ;;
    '["dumb-init","/opt/amnezia/start.sh"]')
        docker exec "$original" grep -q '^# amnezia-managed-ipsec-startup-v1$' /opt/amnezia/start.sh
        legacy_startup=0 ;;
    *) exit 1 ;;
esac
mkdir "$work/build" "$work/preflight"
cp "$stage/Dockerfile" "$work/build/Dockerfile"
docker build --pull --no-cache -t "$name:update-$id" "$work/build"
image=$(docker image inspect -f '{{.Id}}' "$name:update-$id")
[ "$(docker image inspect -f '{{json (index .Config "Entrypoint")}}' "$image")" = '["dumb-init","/opt/amnezia/start.sh"]' ]
docker run --rm --network none --entrypoint ipsec "$image" --version > "$work/new-version"
major=$(sed -n 's/.*Libreswan \([0-9][0-9]*\)\..*/\1/p' "$work/new-version")
[ -n "$major" ] && [ "$major" -ge 5 ]
docker cp "$original:/etc/ipsec.d/ikev2.conf" "$work/preflight/original.conf"
cp "$work/preflight/original.conf" "$work/preflight/candidate.conf"
docker cp "$original:/etc/ipsec.conf" "$work/preflight/main.original"
cp -p "$work/preflight/main.original" "$work/preflight/main.candidate"
# Libreswan 5 changed the default IKEv1 policy. Preserve the old implicit
# behavior without overriding an administrator's explicit policy choice.
if ! grep -Eq '^[[:space:]]*ikev1-policy[[:space:]]*=' "$work/preflight/main.original"; then
    awk '
        /^[ \t]*config[ \t]+setup[ \t]*$/ {count++; print; print "  ikev1-policy=accept"; next}
        {print}
        END {if(count!=1) exit 1}' "$work/preflight/main.original" > "$work/preflight/main.candidate"
fi
cp "$stage/enable_ipv6.sh" "$work/preflight/helper.sh"
docker run --rm --network none --cap-drop ALL -v "$work/preflight:/check" --entrypoint bash "$image" -ec '
    . /check/helper.sh
    amnezia_ipsec_dual_stack_policy
    amnezia_ipsec_migrate_ipv6_config /check/candidate.conf'
. "$stage/network.sh"
identities "$original" > "$work/identities.before"
docker exec "$original" iptables-save > "$work/ipv4.rules"
docker exec "$original" sh -ec '
    interface=$(ip -4 route show default | awk '\''{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}'\'')
    test -n "$interface"
    sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects \
      net.ipv4.conf.all.send_redirects net.ipv4.conf.all.rp_filter \
      net.ipv4.conf.default.accept_redirects net.ipv4.conf.default.send_redirects \
      net.ipv4.conf.default.rp_filter "net.ipv4.conf.$interface.send_redirects" \
      "net.ipv4.conf.$interface.rp_filter"' > "$work/ipv4.sysctl"

touched=1
docker update --restart=no "$original"
docker exec "$original" ipsec whack --shutdown
docker stop "$original"
mkdir "$work/state"
for path in /etc/ipsec.d /etc/ipsec.conf /etc/ipsec.secrets /etc/ppp /etc/xl2tpd /opt/amnezia; do
    docker cp "$original:$path" "$work/state/$(echo "$path" | tr / _)"
done
cmp "$work/preflight/original.conf" "$work/state/_etc_ipsec.d/ikev2.conf"
cmp "$work/preflight/main.original" "$work/state/_etc_ipsec.conf"
docker rename "$original" "$old"
docker create --privileged --restart=no --log-driver none \
    -p "$(cat "$work/binding-500")" -p "$(cat "$work/binding-4500")" \
    --label "amnezia.protocol-update=$id" --name "$name" "$image"
# Start only the image's safe placeholder. The saved state and the new managed
# startup are installed before any VPN daemon is allowed to run.
docker start "$name"
for path in /etc/ipsec.d /etc/ipsec.conf /etc/ipsec.secrets /etc/ppp /etc/xl2tpd /opt/amnezia; do
    case "$path" in
        /etc/ipsec.d|/etc/ppp|/etc/xl2tpd|/opt/amnezia)
            docker exec "$name" mv "$path" "$path.image-$id"
            docker cp "$work/state/$(echo "$path" | tr / _)" "$name:$path"
            ;;
        *) docker cp "$work/state/$(echo "$path" | tr / _)" "$name:$path" ;;
    esac
done
docker cp "$work/preflight/main.candidate" "$name:/etc/ipsec.conf"
docker cp "$work/ipv4.rules" "$name:/opt/amnezia/ipsec-ipv4.rules"
docker cp "$work/ipv4.sysctl" "$name:/opt/amnezia/ipsec-ipv4.sysctl"
# Never execute an old empty/custom startup or the upstream auto-installer.
printf '#!/bin/sh\nexec tail -f /dev/null\n' > "$work/placeholder.sh"
chmod 755 "$work/placeholder.sh"
docker cp "$work/placeholder.sh" "$name:/opt/amnezia/start.sh"
while IFS= read -r network; do
    [ -z "$network" ] || [ "$network" = bridge ] || docker network connect "$network" "$name"
done < "$work/networks"
if [ -n "$AMNEZIA_IPV6_NETWORK" ]; then amnezia_attach_ipv6_network "$name"; fi
docker cp "$stage/start.sh" "$name:/opt/amnezia/start.sh"
docker exec "$name" chmod 755 /opt/amnezia/start.sh
docker exec -d "$name" /opt/amnezia/start.sh
healthy "$name"
identities "$name" > "$work/identities.after"
cmp "$work/identities.before" "$work/identities.after"
docker restart "$name"
healthy "$name"
identities "$name" > "$work/identities.restarted"
cmp "$work/identities.before" "$work/identities.restarted"
docker update --restart="$restart" "$name"
committed=1
result=ok
# Keep stopped original container + root-only snapshot as recovery material.
