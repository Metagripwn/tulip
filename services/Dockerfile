# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-only

ARG ALPINE_VERSION=3.22
ARG GO_VERSION=1.24

### BASE BUILDER
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder
RUN apk add --no-cache git make build-base libpcap-dev vectorscan-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download -x

COPY ./ ./

RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -v ./... \
    && go build -v -o enricher ./cmd/enricher \
    && go build -v -o assembler ./cmd/assembler \
    && go build -v -o api ./cmd/api \
    && go build -v -o mcp ./cmd/mcp \
    && go build -v -o ingestor ./cmd/ingestor

### BASE IMAGE
FROM alpine:${ALPINE_VERSION} AS base
RUN apk add --no-cache ca-certificates vectorscan

### ENRICHER
FROM base AS enricher

WORKDIR /app
COPY --from=builder /build/enricher ./
ENTRYPOINT ["./enricher"]

### ASSEMBLER
FROM base AS assembler
RUN apk add --no-cache libpcap-dev

WORKDIR /app
COPY --from=builder /build/assembler ./
ENTRYPOINT ["./assembler"]

### API
FROM base AS api

WORKDIR /app
COPY --from=builder /build/api ./
ENTRYPOINT ["./api"]

### MCP
FROM base AS mcp

WORKDIR /app
COPY --from=builder /build/mcp ./
ENTRYPOINT ["./mcp"]

FROM base AS ingestor
COPY --from=builder /build/ingestor /app/ingestor
ENTRYPOINT ["/app/ingestor"]

### REMOTE CAPTURE
# This image is intentionally small: it only establishes the SSH stream from
# the local Tulip host to a remote tcpdump process.
FROM alpine:${ALPINE_VERSION} AS remote-capture
RUN apk add --no-cache netcat-openbsd openssh-client
COPY remote-capture/run.sh /app/run.sh
COPY remote-capture/askpass.sh /app/askpass.sh
RUN chmod 0755 /app/run.sh /app/askpass.sh
ENTRYPOINT ["/app/run.sh"]
