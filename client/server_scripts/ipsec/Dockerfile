# OCI multi-platform index, upstream revision 5ff51748, Libreswan 5.4.2.
# Keep a registry-resolvable manifest/index digest, not a local Docker image ID.
FROM hwdsl2/ipsec-vpn-server@sha256:78ea73fb726bc97ccb8c592df88030fe44cb962bdd8cb6cd4da53630bc199374

RUN apk add --no-cache dumb-init && mkdir -p /opt/amnezia \
    && printf '#!/bin/sh\nexec tail -f /dev/null\n' > /opt/amnezia/start.sh \
    && chmod 755 /opt/amnezia/start.sh
LABEL maintainer="AmneziaVPN"
# Amnezia configures identities itself. Do not run the upstream auto-installer.
ENTRYPOINT ["dumb-init", "/opt/amnezia/start.sh"]
CMD []
