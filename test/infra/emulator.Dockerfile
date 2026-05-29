FROM golang:1.26.3 AS builder

ARG EMULATOR_VERSION=master

WORKDIR /app

RUN git clone --branch ${EMULATOR_VERSION} --single-branch https://github.com/ArkLabsHQ/emulator.git

WORKDIR /app/emulator
RUN CGO_ENABLED=0 go build -o /app/bin/emulator ./cmd/emulator.go

FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/emulator /app/emulator

ENV PATH="/app:${PATH}"

VOLUME /app/data

ENTRYPOINT [ "emulator" ]
