# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code and embedded assets
COPY main.go ./
COPY web ./web

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dynamic-proxy .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/dynamic-proxy .

# Copy config file
COPY config.yaml .

# Expose ports
EXPOSE 17283 17284 17285 17286 17287 17288 17289 17290

# Run the application
CMD ["./dynamic-proxy"]
