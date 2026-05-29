FROM golang:1.26.3-alpine AS builder
ARG FULMINE_VERSION=master
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN apk add --no-cache ca-certificates git
RUN git clone --branch ${FULMINE_VERSION} --single-branch https://github.com/ArkLabsHQ/fulmine.git
WORKDIR /src/fulmine
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o /out/mock-boltz ./internal/test/mockboltz

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/mock-boltz /app/mock-boltz
EXPOSE 9101
ENTRYPOINT ["/app/mock-boltz"]
