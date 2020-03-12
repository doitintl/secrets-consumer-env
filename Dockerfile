ARG GO_VERSION=1.14

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --update --no-cache ca-certificates make git curl

RUN mkdir -p /build
WORKDIR /build

COPY go.* /build/
RUN go mod download

COPY . /build
RUN go mod download

COPY . /go/src/${PACKAGE}
RUN CGO_ENABLED=0 go install .

FROM alpine

COPY --from=builder /go/bin/secrets-consumer-env /usr/local/bin/secrets-consumer-env
