ARG BASE=gcr.io/istio-testing/proxyv2:latest

FROM golang:latest AS build

#FROM golang:alpine AS build-base
# dlv doesn't seem to work yet ?

WORKDIR /ws
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=https://proxy.golang.org

RUN apt update && apt install time

COPY go.* ./

RUN go mod download

COPY cmd ./cmd/
COPY pkg ./pkg/
COPY meshcon ./meshcon/
COPY third_party ./third_party/


COPY Makefile ./

ENV OUT=/ws
RUN make build

FROM ${BASE} AS istio

COPY --from=build /ws/krun /usr/local/bin/krun

WORKDIR /

ENTRYPOINT ["/usr/local/bin/krun"]
