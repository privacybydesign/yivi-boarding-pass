# syntax=docker/dockerfile:1

ARG NODE_VERSION=22
ARG GO_VERSION=1.26

# ---------- Frontend build ----------
FROM node:${NODE_VERSION}-bookworm-slim AS frontend-build
WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm install @types/node --save-dev


COPY frontend/ ./
RUN npm run build

# ---------- Backend build ----------
FROM golang:${GO_VERSION}-bookworm AS backend-build
WORKDIR /app/backend

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o server .

# ---------- Runtime ----------
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/backend

# Binaries & assets
COPY --from=backend-build /app/backend/server ./server
COPY --from=frontend-build /app/frontend/dist ../frontend/dist
RUN mkdir -p /app/local-secrets

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["./server", "--config", "config.json"]
