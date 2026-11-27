sudo docker run -d \
--privileged \
--log-driver none \
--restart=always \
-p 500:500/udp \
-p 4500:4500/udp \
--name $CONTAINER_NAME $CONTAINER_NAME

sudo docker network connect amnezia-dns-net $CONTAINER_NAME
if [ -n "$AMNEZIA_IPV6_NETWORK" ]; then
    amnezia_attach_ipv6_network "$CONTAINER_NAME" || exit 1
fi
