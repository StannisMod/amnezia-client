# Run container
sudo docker run -d \
--log-driver none \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p $AWG_SERVER_PORT:$AWG_SERVER_PORT/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name $CONTAINER_NAME \
$CONTAINER_NAME

sudo docker network connect amnezia-dns-net $CONTAINER_NAME
if [ -n "$AMNEZIA_IPV6_NETWORK" ]; then
    sudo docker network connect "$AMNEZIA_IPV6_NETWORK" "$CONTAINER_NAME" || exit 1
    sudo docker exec "$CONTAINER_NAME" sh -c 'mkdir -p /opt/amnezia; touch /opt/amnezia/ipv6-bridge-attached' || exit 1
fi

# Prevent to route packets outside of the container in case if server behind of the NAT
#sudo docker exec -i $CONTAINER_NAME sh -c "ifconfig eth0:0 $SERVER_IP_ADDRESS netmask 255.255.255.255 up"

