FROM node:22 AS web-builder
ARG FULMINE_VERSION=master
WORKDIR /app
RUN git clone --branch ${FULMINE_VERSION} --single-branch https://github.com/ArkLabsHQ/fulmine.git
WORKDIR /app/fulmine/internal/interface/web
RUN rm -rf .parcel-cache && yarn && yarn build

FROM golang:1.26.3 AS go-builder
ARG FULMINE_VERSION=master
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY --from=web-builder /app/fulmine /app/fulmine
WORKDIR /app/fulmine
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /app/bin/fulmine cmd/fulmine/main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=go-builder /app/bin/fulmine /app/fulmine
ENV PATH="/app:${PATH}"
ENV FULMINE_DATADIR=/app/data
VOLUME /app/data
ENTRYPOINT [ "fulmine" ]
