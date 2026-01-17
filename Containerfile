# Build stage
FROM docker.io/library/golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o go-fdo-tool .

# Runtime stage
FROM docker.io/library/alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 fdo && \
    adduser -D -u 1000 -G fdo fdo

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/go-fdo-tool /usr/local/bin/go-fdo-tool

# Copy documentation
COPY --from=builder /build/README.md /app/
COPY --from=builder /build/LICENSE /app/

# Create directory for vouchers
RUN mkdir -p /app/vouchers && \
    chown -R fdo:fdo /app

# Switch to non-root user
USER fdo

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/go-fdo-tool"]

# Default command (show help)
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="go-fdo-tool"
LABEL org.opencontainers.image.description="A command line tool for managing FIDO Device Onboard (FDO) ownership vouchers"
LABEL org.opencontainers.image.url="https://github.com/mmartinv/go-fdo-tool"
LABEL org.opencontainers.image.source="https://github.com/mmartinv/go-fdo-tool"
LABEL org.opencontainers.image.vendor="mmartinv"
LABEL org.opencontainers.image.licenses="MIT"
