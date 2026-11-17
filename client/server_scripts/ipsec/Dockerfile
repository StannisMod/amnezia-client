# OCI multi-platform index, upstream revision f48cd8db, Libreswan 5.4.1.
# Keep a registry-resolvable manifest/index digest, not a local Docker image ID.
FROM hwdsl2/ipsec-vpn-server@sha256:21f2a1b28dbbe69c4331571941df548eee2f4e1cba16af8b161248d66db8d490

RUN apk add --no-cache dumb-init && mkdir -p /opt/amnezia \
    && printf '#!/bin/sh\nexec tail -f /dev/null\n' > /opt/amnezia/start.sh \
    && chmod 755 /opt/amnezia/start.sh
LABEL maintainer="AmneziaVPN"
# Amnezia configures identities itself. Do not run the upstream auto-installer.
ENTRYPOINT ["dumb-init", "/opt/amnezia/start.sh"]
CMD []
