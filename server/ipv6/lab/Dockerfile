FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY native/routing/ ./
RUN go mod download
RUN CGO_ENABLED=0 go test -mod=readonly -tags with_gvisor -c -o /engine.test ./engine
FROM debian:bookworm-slim
RUN apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 update \
 && apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 install -y --no-install-recommends iproute2 iptables python3 util-linux procps \
 && rm -rf /var/lib/apt/lists/*
COPY client/server_scripts/enable_ipv6_forwarding.sh /app/enable_ipv6_forwarding.sh
COPY client/server_scripts/wireguard/start.sh /app/wireguard-start-source.sh
COPY client/server_scripts/awg/start.sh /app/awg-start-source.sh
COPY client/server_scripts/awg_legacy/start.sh /app/awg-legacy-start-source.sh
RUN for kind in wireguard awg awg-legacy; do \
      { head -n 1 /app/$kind-start-source.sh; cat /app/enable_ipv6_forwarding.sh; tail -n +2 /app/$kind-start-source.sh; } > /app/$kind-start.sh; \
    done
COPY server/ipv6/lab/run.sh /app/run.sh
COPY server/ipv6/lab/test_forwarding.py /app/test_forwarding.py
COPY server/ipv6/lab/test_boot.py /app/test_boot.py
COPY server/ipv6/lab/run_boot.sh /app/run_boot.sh
COPY server/ipv6/lab/run_encrypted.sh /app/run_encrypted.sh
COPY --from=build /engine.test /app/engine.test
ENTRYPOINT ["sh", "/app/run.sh"]
