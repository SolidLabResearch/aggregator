FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o cleaner

FROM gcr.io/distroless/base
COPY --from=builder /app/cleaner /cleaner
ENTRYPOINT ["/cleaner"]
