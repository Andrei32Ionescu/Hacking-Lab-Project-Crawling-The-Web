FROM golang:1.23

WORKDIR /go/src/hakrawler

# Install Chrome dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN go mod download
RUN go build -o /go/bin/hakrawler .

ENTRYPOINT ["/go/bin/hakrawler"]