ARG BASE_IMAGE=eclipse-temurin:17-jdk-jammy
FROM ${BASE_IMAGE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 openvpn openssl iproute2 nftables \
 && rm -rf /var/lib/apt/lists/*
# Mount the checkout read-only at /src, Android SDK at ANDROID_HOME, and share
# only an owned emulator container's namespace. No host network/Docker socket.
ENTRYPOINT ["python3", "/src/scripts/routing/run_android_openvpn_acceptance.py"]
