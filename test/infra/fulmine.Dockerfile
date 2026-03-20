# Build fulmine from source (used as boltz-fulmine sidecar for Boltz backend)
FROM golang:1.26.1 AS go-builder

ARG VERSION
ARG TARGETOS
ARG TARGETARCH
ARG FULMINE_BRANCH=master

WORKDIR /app
RUN git clone --branch ${FULMINE_BRANCH} --single-branch --depth 1 https://github.com/ArkLabsHQ/fulmine.git .

# Build without web assets (not needed for boltz-fulmine sidecar)
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-X 'main.version=${VERSION}'" -o bin/fulmine cmd/fulmine/main.go

# Final image
FROM alpine:3.20

WORKDIR /app

COPY --from=go-builder /app/bin/* /app/

ENV PATH="/app:${PATH}"
ENV FULMINE_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "fulmine" ]
