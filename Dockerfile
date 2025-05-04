FROM golang:1.21-alpine

WORKDIR /app

# Install git for go mod download
RUN apk add --no-cache git

# Copy source code
COPY . .

# Download dependencies and verify
RUN go mod tidy

# Build the application
RUN go build -o webcrawler .

# Make run script executable
RUN chmod +x run.sh

ENTRYPOINT ["./run.sh"]