#!/bin/sh
# Run through sudo sh. Arguments and build directory are validated by the app.
set -eu
build=$1
host=$2
name=amnezia-connection-updates
volume=amnezia-connection-updates-state
if docker container inspect "$name" >/dev/null 2>&1; then
    test "$(docker inspect -f '{{index .Config.Labels "org.amnezia.connection-updates"}}' "$name")" = 1
    test "$(docker inspect -f '{{.State.Running}}' "$name")" = true
    docker exec "$name" /updates info </dev/null
    exit
fi
# Do not overwrite another service's volume or expose an uninitialized service.
if docker volume inspect "$volume" >/dev/null 2>&1; then
    test "$(docker volume inspect -f '{{index .Labels "org.amnezia.connection-updates"}}' "$volume")" = 1
else
    docker volume create --label org.amnezia.connection-updates=1 "$volume" >/dev/null
fi
docker build --network host -t amnezia-connection-updates:1 "$build" >/dev/null
# The request contains a normalized hostname only; no VPN credentials or tokens.
printf '{"host":"%s"}' "$host" | docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=volume,source=$volume,target=/data" amnezia-connection-updates:1 init >/dev/null
docker run -d --name "$name" --restart unless-stopped --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 128m --label org.amnezia.connection-updates=1 -p 8443:8443/tcp --mount "type=volume,source=$volume,target=/data,readonly" amnezia-connection-updates:1 >/dev/null
# Admin CLI needs a separate writable volume mount. The serving process is read-only.
docker exec "$name" /updates info </dev/null
