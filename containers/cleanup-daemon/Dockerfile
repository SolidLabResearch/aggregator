FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY main.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o cleanup-daemon main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/cleanup-daemon .

EXPOSE 9999

CMD ["./cleanup-daemon"]

