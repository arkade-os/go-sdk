# First image used to build the sources
FROM golang:1.25.5 AS builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

RUN git clone --branch ark-asset --single-branch https://github.com/arkade-os/arkd.git

# ENV GOPROXY=https://goproxy.io,direct
RUN cd arkd && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ../bin/arkd ./cmd/arkd
RUN cd arkd/pkg/ark-cli && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${VERSION}'" -o ../../../bin/ark main.go

# Second image, running the arkd executable
FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/* /app/

ENV PATH="/app:${PATH}"
ENV ARKD_DATADIR=/app/data

# Expose volume containing all 'arkd' data
VOLUME /app/data

ENTRYPOINT [ "arkd" ]
