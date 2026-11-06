FROM amnezia-local-full-build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables tcpdump dbus network-manager python3 udev \
    && rm -rf /var/lib/apt/lists/*
