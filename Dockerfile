FROM golang:1.24

WORKDIR /app

# Install Air for hot reload (pinned to avoid Go 1.25 requirement)
RUN go install github.com/air-verse/air@v1.61.1

COPY go.mod ./
# COPY go.sum ./ # No go.sum yet

# Download dependencies
RUN go mod download

COPY . .

CMD ["air"]
