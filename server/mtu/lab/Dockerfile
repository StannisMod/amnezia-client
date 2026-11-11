FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY native/routing/ ./
RUN go mod download
RUN CGO_ENABLED=0 go build -mod=readonly -tags with_gvisor -o /bin/lab/amnezia-routing ./cmd/amnezia-routing
RUN CGO_ENABLED=0 go test -mod=readonly -tags with_gvisor -c -o /bin/lab/engine.test ./engine
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y python3 iproute2 nftables tcpdump util-linux procps && rm -rf /var/lib/apt/lists/*
COPY --from=build /bin/lab/ /bin/lab/
COPY server/mtu/ /controller/
COPY server/mtu/lab/ /lab/
ENTRYPOINT ["bash","/lab/run.sh"]
