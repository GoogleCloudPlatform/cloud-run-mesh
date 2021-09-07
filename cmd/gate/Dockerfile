ARG BASE=gcr.io/wlhe-cr/krun:main

FROM golang:latest AS build

#FROM golang:alpine AS build-base
# dlv doesn't seem to work yet ?

WORKDIR /ws
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOPROXY=https://proxy.golang.org

COPY go.* ./
# Helps speed up local builds
RUN go mod download

COPY cmd ./cmd/
COPY pkg ./pkg/

RUN go build -a -gcflags='all=-N -l' -ldflags '-extldflags "-static"' -o /ws/hgate ./cmd/gate

FROM ${BASE} AS istio

COPY --from=build /ws/hgate /usr/local/bin/hgate

WORKDIR /

ENTRYPOINT ["/usr/local/bin/hgate"]
