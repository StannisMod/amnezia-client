FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod service.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /updates .
FROM scratch
COPY --from=build /updates /updates
LABEL org.amnezia.connection-updates="1"
ENTRYPOINT ["/updates"]
CMD ["serve"]
