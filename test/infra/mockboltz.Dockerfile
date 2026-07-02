FROM golang:1.26.3-alpine AS builder
# Pin to the last Fulmine revision that still ships internal/test/mockboltz.
ARG FULMINE_VERSION=48d887005f0a13075705bb75b1fd94d5cbc47793
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN apk add --no-cache ca-certificates git
RUN git init fulmine && \
    cd fulmine && \
    git remote add origin https://github.com/ArkLabsHQ/fulmine.git && \
    git fetch --depth 1 origin ${FULMINE_VERSION} && \
    git checkout --detach FETCH_HEAD
WORKDIR /src/fulmine
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o /out/mock-boltz ./internal/test/mockboltz

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/mock-boltz /app/mock-boltz
EXPOSE 9101
ENTRYPOINT ["/app/mock-boltz"]
