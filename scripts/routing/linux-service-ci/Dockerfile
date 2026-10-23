FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus libnss-resolve sudo psmisc python3 iproute2 nftables iptables \
    ca-certificates procps libsecret-1-0 libxkbcommon-x11-0 libxcb-icccm4 \
    libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-xinerama0 \
    libxcb-cursor0 libxcb-shape0 libxcb-xfixes0 libxcb-randr0 libgl1 libegl1 \
    libdbus-1-3 libfontconfig1 libglib2.0-0 libx11-xcb1 libopengl0 \
    && mkdir -p /usr/share/applications /usr/share/pixmaps \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
