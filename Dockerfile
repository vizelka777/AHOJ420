FROM golang:1.24

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN /usr/local/go/bin/go mod download

COPY . .

RUN /usr/local/go/bin/go build -o /usr/local/bin/ahoj420 ./cmd/server/main.go

CMD ["/usr/local/bin/ahoj420"]
