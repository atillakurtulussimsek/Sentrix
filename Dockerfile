# syntax=docker/dockerfile:1
# Sentrix server image: server + CLI, plus agent binaries for the install.sh one-liner.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ENV CGO_ENABLED=0
RUN LDFLAGS="-s -w -X github.com/atillakurtulussimsek/Sentrix/internal/version.Version=${VERSION} -X github.com/atillakurtulussimsek/Sentrix/internal/version.Commit=${COMMIT} -X github.com/atillakurtulussimsek/Sentrix/internal/version.Date=${DATE}" && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "$LDFLAGS" -o /out/sentrix-server ./cmd/sentrix-server && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "$LDFLAGS" -o /out/sentrix ./cmd/sentrix && \
    for a in amd64 arm64; do GOOS=linux GOARCH=$a go build -trimpath -ldflags "$LDFLAGS" -o /out/agents/sentrix-agent-linux-$a ./cmd/sentrix-agent; done && \
    mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sentrix-server /out/sentrix /usr/local/bin/
COPY --from=build /out/agents /usr/share/sentrix/agents
COPY --from=build --chown=65532:65532 /out/data /data
ENV SENTRIX_DATA_DIR=/data \
    SENTRIX_LISTEN=:8080 \
    SENTRIX_GATEWAY_LISTEN=:8443 \
    SENTRIX_AGENT_DIR=/usr/share/sentrix/agents
VOLUME ["/data"]
EXPOSE 8080 8443
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/sentrix-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sentrix-server"]
CMD ["serve"]
