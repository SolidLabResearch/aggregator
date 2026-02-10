FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o token-service

FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/token-service .

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/token-service"]
