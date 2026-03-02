FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /out/geodns ./cmd/geodns
FROM alpine:3.20
RUN adduser -D app
WORKDIR /app
COPY --from=builder /out/geodns /app/geodns
COPY docker/entrypoint.sh /entrypoint.sh
USER app
EXPOSE 53/udp 53/tcp 5555
ENTRYPOINT ["/entrypoint.sh"]
