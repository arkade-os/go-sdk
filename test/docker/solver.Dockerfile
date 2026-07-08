FROM golang:1.26.3 AS builder

# Keep this pinned while TestNonInteractiveClaim depends on the solver
# preimage plugin and /v1/plugins readiness endpoint.
ARG SOLVER_VERSION=9005e421e8af22825d83ffbd01df932eb983da10

WORKDIR /app

RUN git clone https://github.com/arkade-os/solver.git

WORKDIR /app/solver
RUN git checkout --detach ${SOLVER_VERSION}
RUN CGO_ENABLED=0 go build -o /app/bin/solverd ./cmd/solverd

FROM alpine:3.20

RUN apk update && apk upgrade

WORKDIR /app

COPY --from=builder /app/bin/solverd /app/solverd

ENV PATH="/app:${PATH}"
ENV SOLVER_DATADIR=/app/data

VOLUME /app/data

ENTRYPOINT [ "solverd" ]
