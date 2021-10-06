ARG BASE=gcr.io/istio-testing/proxyv2:latest

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
#RUN go mod download

COPY cmd ./cmd/
COPY pkg ./pkg/

ENV OUT=/ws
RUN make build

FROM ${BASE} AS istio

COPY --from=build /ws/krun /usr/local/bin/krun

WORKDIR /

ENTRYPOINT ["/usr/local/bin/krun"]
