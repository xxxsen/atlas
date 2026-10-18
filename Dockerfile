# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine3.24@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
    -o /out/atlas ./cmd/atlas

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 atlas \
    && adduser -S -D -H -u 10001 -G atlas atlas \
    && install -d -o atlas -g atlas /data

COPY --from=builder --chown=atlas:atlas /out/atlas /usr/local/bin/atlas

WORKDIR /data
EXPOSE 5353/tcp 5353/udp 6060/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/atlas"]
