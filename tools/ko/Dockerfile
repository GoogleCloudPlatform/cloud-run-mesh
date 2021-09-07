# Specialized builder - should include all deps.


FROM golang:alpine AS kosource

ARG KO_GIT_TAG=main
RUN apk update && apk add gcc bash musl-dev openssl-dev ca-certificates make git && update-ca-certificates

RUN git clone --depth=1 -b "${KO_GIT_TAG}" https://github.com/google/ko
WORKDIR ko
RUN GOOS=linux go build -mod=vendor -o /bin/ko ./


FROM golang:alpine

COPY --from=kosource /bin/ko /usr/local/bin/ko

ENV GOPATH=""

# To avoid downloads when building. The builder should be rebuilt on dep changes
#COPY go.* ./
#RUN go mod download

ENTRYPOINT ["/bin/sh"]
