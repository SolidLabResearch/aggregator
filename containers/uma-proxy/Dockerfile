# Use the official Golang image as the base image
FROM golang:1.23 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod ./
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 go build -ldflags="-extldflags=-static" -o uma-proxy .

# Use a minimal base image for the final container
FROM alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/uma-proxy .

# Expose the port the proxy listens on
EXPOSE 8080
EXPOSE 8443

# Command to run the proxy
CMD ["./uma-proxy"]
