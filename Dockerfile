# ==============================================================================
# STAGE 1: Build the Next.js Frontend (HadesGate Industrial Brutalist UI)
# ==============================================================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-fund

COPY frontend/ ./
RUN npm run build

# ==============================================================================
# STAGE 2: Build the High-Performance Go Binary (CGO_ENABLED=0 + Pure-Go SQLite)
# ==============================================================================
FROM golang:1.27.4-alpine AS go-builder
WORKDIR /app

COPY go.mod go.sum ./
COPY . .

# Copy static frontend export into Go embed directory
COPY --from=frontend-builder /app/frontend/out ./internal/web/dist

# Build fully static Linux ELF binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o hadesgate \
    ./cmd/hadesgate

# ==============================================================================
# STAGE 3: Ultra-compact Runtime Image
# ==============================================================================
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata && update-ca-certificates

WORKDIR /app

COPY --from=go-builder /app/hadesgate /app/hadesgate

# Create unprivileged user and writable SQLite data directory
RUN adduser -D -u 10001 hadesgate && \
    mkdir -p /app/data && \
    chown -R hadesgate:hadesgate /app/data
USER hadesgate:hadesgate

EXPOSE 8080

ENTRYPOINT ["/app/hadesgate"]
