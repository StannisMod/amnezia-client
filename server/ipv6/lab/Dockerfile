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
COPY server/ipv6/lab/run.sh /app/run.sh
COPY server/ipv6/lab/test_forwarding.py /app/test_forwarding.py
COPY server/ipv6/lab/run_encrypted.sh /app/run_encrypted.sh
COPY --from=build /engine.test /app/engine.test
ENTRYPOINT ["sh", "/app/run.sh"]
