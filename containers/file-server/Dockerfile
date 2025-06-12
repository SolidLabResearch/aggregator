FROM golang:1.23-alpine

WORKDIR /app

COPY . .

RUN go build -o file-server .

EXPOSE 8080

CMD ["./file-server"]
