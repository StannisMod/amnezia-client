FROM hwdsl2/ipsec-vpn-server@sha256:9ae4084cf5c93bced92551fbfffa5872291e21c84e6b1c2b46ab69eea5bacab1

RUN apk add --no-cache dumb-init && mkdir -p /opt/amnezia \
    && printf '#!/bin/sh\nexec tail -f /dev/null\n' > /opt/amnezia/start.sh \
    && chmod 755 /opt/amnezia/start.sh
LABEL maintainer="AmneziaVPN"
# Amnezia configures identities itself. Do not run the upstream auto-installer.
ENTRYPOINT ["dumb-init", "/opt/amnezia/start.sh"]
CMD []
