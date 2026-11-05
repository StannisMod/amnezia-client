#!/bin/sh
# Run as root on the server. Never run configure_container.sh during an update:
# it generates a new identity. Keep the original container for rollback instead.
set -eu
umask 077

kind=$1
stage=$2
case "$kind" in
    wireguard) name=amnezia-wireguard; tool=wg; iface=wg0; config=/opt/amnezia/wireguard/wg0.conf ;;
    awg) name=amnezia-awg2; tool=awg; iface=awg0; config=/opt/amnezia/awg/awg0.conf ;;
    *) exit 1 ;;
esac
case "$stage" in /tmp/amnezia-update-*) ;; *) exit 1 ;; esac
id=${stage#/tmp/amnezia-update-}
case "$id" in ''|*[!a-f0-9-]*) exit 1 ;; esac

exec 3>&1
mkdir -p /var/lib/amnezia/updates
chmod 700 /var/lib/amnezia/updates
exec 9>"/var/lib/amnezia/updates/$name.lock"
if ! flock -n 9; then
    echo 'amnezia_update=busy' >&3
    exit 1
fi
work="/var/lib/amnezia/updates/$name-$id"
mkdir "$work"
exec >"$work/update.log" 2>&1
old="$name-backup-$id"
image="$name:update-$id"
touched=0
committed=0
result=rejected
restart=always
legacy_awg=0

finish() {
    trap - EXIT HUP INT TERM
    if [ "$committed" = 0 ] && [ "$touched" = 1 ]; then
        result=rollback_failed
        restored=1
        # Resolve by immutable identity, including signals between a Docker
        # command and the next shell assignment. Never remove an unrelated
        # container that another administrator may have placed at this name.
        current_id=$(docker inspect -f '{{.Id}}' "$name" 2>/dev/null) || current_id=''
        if [ -n "$current_id" ] && [ "$current_id" != "$original_id" ]; then
            owner=$(docker inspect -f '{{index .Config.Labels "amnezia.protocol-update"}}' "$current_id") || owner=''
            if [ "$owner" = "$id" ]; then
                docker rm -f "$current_id" || restored=0
            else
                restored=0
            fi
        fi
        original_name=$(docker inspect -f '{{.Name}}' "$original_id") || original_name=''
        if [ "$original_name" != "/$name" ]; then
            docker rename "$original_id" "$name" || restored=0
        fi
        docker update --restart="$restart" "$original_id" || restored=0
        docker start "$original_id" || restored=0
        if [ "$restored" = 1 ] && healthy "$original_id"; then
            result=rolled_back
        fi
    fi
    printf '%s\n' "$result" >"$work/result"
    printf 'amnezia_update=%s\n' "$result" >&3
}
trap finish EXIT
trap 'exit 1' HUP INT TERM

# A live interface, rather than a running tail process, defines readiness.
healthy() {
    attempt=0
    while [ "$attempt" -lt 15 ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$1")" = true ] &&
            docker exec "$1" "$tool" show "$iface" >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}

# Preserve the association of each peer with its PSK/allowed IPs. Endpoint is
# roaming state; counters and handshake timestamps aren't part of showconf.
canonical() {
    awk '/^\[Peer\]/ {peer=""; next}
         /^PublicKey = / {peer=$0; next}
         /^Endpoint = / {next}
         /^(RandomTrailers|DisableCookies) = off$/ {next}
         NF {print peer "|" $0}' "$1" | LC_ALL=C sort
}

[ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ]
original_id=$(docker inspect -f '{{.Id}}' "$name")
healthy "$name"
# Only standard Amnezia containers are supported. Do not silently discard
# custom mounts or host networking when replacing a container.
docker inspect -f '{{.HostConfig.NetworkMode}}' "$name" >"$work/network-mode"
case "$(cat "$work/network-mode")" in default|bridge) ;; *) exit 1 ;; esac
docker inspect -f '{{range .Mounts}}{{println .Destination}}{{end}}' "$name" >"$work/mounts"
if awk 'NF && $0 != "/lib/modules" {bad=1} END {exit !bad}' "$work/mounts"; then exit 1; fi
restart=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$name")
case "$restart" in always|unless-stopped|no) ;; *) exit 1 ;; esac
docker inspect "$name" >"$work/original-container.json"
docker inspect -f '{{range $key, $value := .NetworkSettings.Networks}}{{println $key}}{{end}}' "$name" >"$work/networks"
docker exec "$name" cat "$config" >"$work/server.conf"
if [ "$kind" = awg ]; then
    # AWG 3 can keep serving AWG 2 profiles when their wire parameters are
    # retained. Never generate/enable header protection as part of this update.
    # Require AWG 2/3 settings; legacy amnezia-awg (1.x) is a separate container.
    if grep -Eq '^[[:space:]]*HeaderProtectionKey[[:space:]]*=[[:space:]]*[^[:space:]]' "$work/server.conf"; then
        printf '%s\n' awg3 >"$work/protocol-mode"
    else
        grep -Eq '^[[:space:]]*(S[34][[:space:]]*=|H[1-4][[:space:]]*=[[:space:]]*[0-9]+-[0-9]+)' "$work/server.conf"
        # Binary migration has been qualified for the userspace daemon. A
        # host kernel module is outside this container-software transaction.
        docker exec "$name" test -e "/sys/class/net/$iface/tun_flags"
        legacy_awg=1
        printf '%s\n' awg2-compatible >"$work/protocol-mode"
    fi
fi
port=$(awk '$1 == "ListenPort" && $2 == "=" {print $3}' "$work/server.conf")
case "$port" in ''|*[!0-9]*) exit 1 ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ]
# Ensure the stored listen port matches the published port, before touching VPN.
[ "$(docker inspect -f '{{len .HostConfig.PortBindings}}' "$name")" = 1 ]
[ "$(docker inspect -f "{{len (index .HostConfig.PortBindings \"$port/udp\")}}" "$name")" = 1 ]
host_ip=$(docker inspect -f "{{(index (index .HostConfig.PortBindings \"$port/udp\") 0).HostIp}}" "$name")
case "$host_ip" in ''|0.0.0.0) ;; *) exit 1 ;; esac
[ "$(docker inspect -f "{{(index (index .HostConfig.PortBindings \"$port/udp\") 0).HostPort}}" "$name")" = "$port" ]
docker exec "$name" "$tool" --version >"$work/old-tools-version"
if [ "$kind" = awg ]; then
    docker exec "$name" amneziawg-go --version >"$work/old-daemon-version"
fi
mkdir "$work/build"
cp "$stage/Dockerfile" "$work/build/Dockerfile"
# Build while the old VPN is still serving. Pin all subsequent steps to the
# resulting image ID; do not resolve the mutable upstream tag a second time.
docker build --pull --no-cache -t "$image" "$work/build"
image_id=$(docker image inspect -f '{{.Id}}' "$image")
printf '%s\n' "$image_id" >"$work/target-image"
docker run --rm --network none --entrypoint "$tool" "$image_id" --version >"$work/new-tools-version"
if [ "$kind" = awg ]; then
    docker run --rm --network none --entrypoint amneziawg-go "$image_id" --version >"$work/new-daemon-version"
    if [ "$legacy_awg" = 1 ]; then
        # Upstream's --version may still contain an old date. Qualify the
        # standard AWG 3 main module, rather than trusting the mutable tag.
        docker run --rm --network none --entrypoint sh "$image_id" -c \
            'strings /usr/bin/amneziawg-go | grep -q "^path[[:space:]]github[.]com/amnezia-vpn/amneziawg-go/v3$"'
    fi
fi
docker exec "$name" "$tool" showconf "$iface" >"$work/expected.conf"

touched=1
docker update --restart=no "$name"
docker stop "$name"
# Copy after stop, so config, keys and clientsTable belong to one snapshot.
mkdir "$work/state"
docker cp "$name:/opt/amnezia/." "$work/state/"
cmp "$work/server.conf" "$work/state/${config#/opt/amnezia/}"
docker rename "$name" "$old"
docker create --log-driver none --restart=no --privileged \
    --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
    -p "$port:$port/udp" -v /lib/modules:/lib/modules \
    --sysctl=net.ipv4.conf.all.src_valid_mark=1 \
    --label "amnezia.protocol-update=$id" --name "$name" "$image_id"
docker cp "$work/state/." "$name:/opt/amnezia/"
while IFS= read -r network; do
    [ -z "$network" ] || [ "$network" = bridge ] || docker network connect "$network" "$name"
done <"$work/networks"
docker start "$name"
healthy "$name"
[ "$legacy_awg" = 0 ] || docker exec "$name" test -e "/sys/class/net/$iface/tun_flags"
# Verify the effective runtime accepts every saved peer/key/parameter, not just
# that the container's startup script managed to reach its tail command.
docker exec "$name" "$tool" showconf "$iface" >"$work/actual.conf"
canonical "$work/expected.conf" >"$work/expected.normalized"
canonical "$work/actual.conf" >"$work/actual.normalized"
cmp "$work/expected.normalized" "$work/actual.normalized"
# Check a restart too: startup must work from the preserved on-disk state.
docker restart "$name"
healthy "$name"
[ "$legacy_awg" = 0 ] || docker exec "$name" test -e "/sys/class/net/$iface/tun_flags"
docker exec "$name" "$tool" showconf "$iface" >"$work/restarted.conf"
canonical "$work/restarted.conf" >"$work/restarted.normalized"
cmp "$work/expected.normalized" "$work/restarted.normalized"
docker update --restart="$restart" "$name"
committed=1
result=ok
# Keep both the root-only snapshot and stopped old container. No automatic prune:
# these are recovery material, not disposable build files.
