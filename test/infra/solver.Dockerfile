FROM golang:1.26.3 AS builder

ARG SOLVER_VERSION=master

WORKDIR /app

RUN git clone --branch ${SOLVER_VERSION} --single-branch https://github.com/arkade-os/solver.git

WORKDIR /app/solver
RUN CGO_ENABLED=0 go build -o /app/bin/solverd ./cmd/solverd

FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/solverd /app/solverd

ENV PATH="/app:${PATH}"
ENV SOLVER_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "solverd" ]
