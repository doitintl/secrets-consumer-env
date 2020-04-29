ARG GO_VERSION=1.14

FROM golang:${GO_VERSION}-alpine AS builder
ARG VERSION
ARG COMMIT

RUN apk add --update --no-cache ca-certificates make git curl

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download

COPY . /build
RUN go mod download

COPY . /go/src/${PACKAGE}

RUN go build -ldflags="-X github.com/doitintl/secrets-consumer-env/pkg/version.version=${VERSION} -X github.com/doitintl/secrets-consumer-env/pkg/version.gitCommitID=${COMMIT}"
RUN cp secrets-consumer-env /usr/local/bin/
RUN chmod a+x /usr/local/bin/secrets-consumer-env

FROM alpine

COPY --from=builder /usr/local/bin/secrets-consumer-env /usr/local/bin/secrets-consumer-env
