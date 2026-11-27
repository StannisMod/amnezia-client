FROM amnezia-local-full-build
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,id=amnezia-stability-apt-${TARGETARCH},target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=amnezia-stability-apt-lists-${TARGETARCH},target=/var/lib/apt/lists,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables tcpdump dbus network-manager python3 udev
