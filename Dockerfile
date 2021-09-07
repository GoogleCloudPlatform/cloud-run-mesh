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

RUN go build -a -gcflags='all=-N -l' -ldflags '-extldflags "-static"' -o /ws/krun ./cmd/krun


FROM ${BASE} AS istio

# Similar with the 'ko' runtime layout
COPY --from=build /ws/krun /ko-app/krun

WORKDIR /

ENTRYPOINT ["/ko-app/krun"]
