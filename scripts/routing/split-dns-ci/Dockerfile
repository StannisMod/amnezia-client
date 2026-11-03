FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    dbus systemd-resolved iproute2 nftables python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
