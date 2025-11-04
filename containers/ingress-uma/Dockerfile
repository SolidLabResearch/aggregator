# Step 1. Build the Go binary
FROM golang:1.24.4-alpine AS builder

# Enable Go modules and install dependencies
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build static binary
RUN go build -o ingress-uma .

############################################################

# Step 2. Final image
FROM alpine:3.20

# Add certificates (in case we fetch JWKS etc later)
RUN apk add --no-cache ca-certificates

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/ingress-uma .

# Expose port for Kubernetes
EXPOSE 8080

# Provide default env vars (optional)
ENV LOG_LEVEL=info

# Run the binary
CMD ["/app/ingress-uma"]