FROM golang:1.27.2-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY native/routing/go.mod native/routing/go.sum ./
RUN go mod download && go mod verify
COPY native/routing/ ./
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -tags with_gvisor -o /bin/lab/amnezia-routing ./cmd/amnezia-routing \
 && CGO_ENABLED=0 go test -mod=readonly -tags with_gvisor -c -o /bin/lab/engine.test ./engine \
 && python3 internal/builddeps/verify.py --module . --binary /bin/lab/amnezia-routing --output /bin/lab/tcp-dependency.json \
 && python3 licenses/generate.py --module . --output /bin/lab/routing-licenses
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 iproute2 nftables conntrack tcpdump util-linux procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /bin/lab /opt/lab/bin
COPY scripts/routing/chaos/ /opt/lab/
COPY LICENSE /opt/lab/LICENSE
ENTRYPOINT ["python3","/opt/lab/run.py"]
