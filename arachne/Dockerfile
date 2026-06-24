# ArachneC2 Simulator — Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o arachne ./cmd/arachne

FROM alpine:3.19 AS runtime
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/arachne .
ENTRYPOINT ["./arachne"]
CMD ["--config", "/app/arachne.json"]
