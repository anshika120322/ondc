FROM golang:1.21-alpine

WORKDIR /app

# Copy go module files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

CMD ["go", "test", "-v"]
