# ------------------------
# Stage 1: Build Go aggregator
# ------------------------
FROM golang:1.23-alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o aggregator .

# ------------------------
# Stage 2: Minimal runtime
# ------------------------
FROM alpine:latest

WORKDIR /root/
# Copy the compiled binary from build stage
COPY --from=build /app/aggregator .

# Expose internal port
EXPOSE 5000

# Run the aggregator
CMD ["./aggregator"]
