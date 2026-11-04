#!/bin/sh
# Run as root through SSH. Source lives in the caller's private staging directory.
set -eu
build=$1
host=$2
name=amnezia-connection-updates
volume=amnezia-connection-updates-state
original_id=''
original_running=false
original_restart=unless-stopped
candidate_id=''
committed=0
touched=0
operation=$(cat /proc/sys/kernel/random/uuid)
backup="$name-backup-$operation"
if docker container inspect "$name" >/dev/null 2>&1; then
    test "$(docker inspect -f '{{index .Config.Labels "org.amnezia.connection-updates"}}' "$name")" = 1
    original_id=$(docker inspect -f '{{.Id}}' "$name")
    original_running=$(docker inspect -f '{{.State.Running}}' "$original_id")
    original_restart=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$original_id")
    case "$original_restart" in no|always|unless-stopped) ;; *) exit 1 ;; esac
fi
if docker volume inspect "$volume" >/dev/null 2>&1; then
    test "$(docker volume inspect -f '{{index .Labels "org.amnezia.connection-updates"}}' "$volume")" = 1
else
    docker volume create --label org.amnezia.connection-updates=1 "$volume" >/dev/null
fi
# Do not fill the SSH stderr channel with a long image-build log.
docker build --network host -t amnezia-connection-updates:1 "$build" >"$build/build.log" 2>&1
image=$(docker image inspect -f '{{.Id}}' amnezia-connection-updates:1)
printf '{"host":"%s"}' "$host" | docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=volume,source=$volume,target=/data" "$image" init >/dev/null
if [ -n "$original_id" ] && [ "$(docker inspect -f '{{.Image}}' "$original_id")" = "$image" ] && [ "$original_running" = true ]; then
    docker exec "$original_id" /updates probe </dev/null >/dev/null
    docker exec "$original_id" /updates info </dev/null
    exit
fi
finish() {
    trap - EXIT HUP INT TERM
    if [ "$touched" = 1 ] && [ "$committed" = 0 ]; then
        # Resolve only our candidate. Never remove another service at this name.
        current=$(docker inspect -f '{{.Id}}' "$name" 2>/dev/null) || current=''
        if [ -n "$current" ] && [ "$current" != "$original_id" ]; then
            owner=$(docker inspect -f '{{index .Config.Labels "amnezia.delivery-upgrade"}}' "$current") || owner=''
            if [ "$owner" = "$operation" ]; then docker rm -f "$current" >/dev/null || true; fi
        fi
        if [ -n "$original_id" ]; then
            previous_name=$(docker inspect -f '{{.Name}}' "$original_id") || previous_name=''
            if [ "$previous_name" != "/$name" ]; then docker rename "$original_id" "$name" || true; fi
            docker update --restart="$original_restart" "$original_id" >/dev/null || true
            if [ "$original_running" = true ]; then docker start "$original_id" >/dev/null || true; fi
        fi
    fi
}
trap finish EXIT
trap 'exit 1' HUP INT TERM
touched=1
if [ -n "$original_id" ]; then
    docker stop "$original_id" >/dev/null
    docker update --restart=no "$original_id" >/dev/null
    docker rename "$original_id" "$backup"
fi
candidate_id=$(docker run -d --name "$name" --restart unless-stopped --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 128m --tmpfs /run/amnezia-updates:rw,nosuid,nodev,noexec,size=2m,mode=0700 --label org.amnezia.connection-updates=1 --label "amnezia.delivery-upgrade=$operation" -p 8443:8443/tcp --mount "type=volume,source=$volume,target=/data,readonly" "$image")
attempt=0
while [ "$attempt" -lt 15 ]; do
    if docker exec "$candidate_id" /updates probe </dev/null >/dev/null 2>&1; then break; fi
    attempt=$((attempt + 1))
    sleep 1
done
[ "$attempt" -lt 15 ]
docker exec "$candidate_id" /updates info </dev/null
committed=1
