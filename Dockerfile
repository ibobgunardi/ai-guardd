FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
# COPY go.sum ./
# RUN go mod download
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static build to avoid dependency on libc availability in scratch/alpine
RUN CGO_ENABLED=0 GOOS=linux go build -o ai-guardd ./cmd/ai-guardd

FROM alpine:latest
WORKDIR /app
# 1. Create non-root user/group
RUN addgroup -S aiguard && adduser -S aiguard -G aiguard
# 2. Copy binary
COPY --from=builder /app/ai-guardd /usr/local/bin/
# 3. Setup permissions for config/logs (Must exist and be writable by aiguard)
RUN mkdir -p /etc/ai-guardd /var/log/ai-guardd && \
    chown -R aiguard:aiguard /etc/ai-guardd /var/log/ai-guardd

# 4. Switch User
USER aiguard

CMD ["ai-guardd", "run", "--config", "/etc/ai-guardd/config.yml"]
