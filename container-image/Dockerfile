# Build stage
FROM golang:1.25 AS builder

WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Cache deps
RUN go mod download

# Copy the source code
COPY cmd/ cmd/
COPY internal/ internal/

# Build
# CGO_ENABLED=0 is usually preferred for static binaries, but if iptables interactions needed cgo (unlikely for exec calls), leave it.
# The code usesos/exec to call binaries, so purely static go binary is fine.
RUN CGO_ENABLED=0 GOOS=linux go build -a -o metaleg-agent cmd/metaleg-agent/main.go

# Runtime stage
FROM alpine:edge

# Install runtime dependencies
RUN apk add --no-cache \
    iptables \
    ipset \
    ca-certificates

WORKDIR /
COPY --from=builder /workspace/metaleg-agent .

ENTRYPOINT ["/metaleg-agent"]
