# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Specialized builder - should include all deps.


FROM golang:1.16 AS kosource
ARG KO_GIT_TAG=main

RUN git clone --depth=1 -b "${KO_GIT_TAG}" https://github.com/google/ko
WORKDIR ko
RUN GOOS=linux go build -mod=vendor -o /bin/ko ./


FROM docker:stable as docker
FROM gcr.io/istio-testing/proxyv2:latest as istio

FROM gcr.io/cloud-builders/kubectl

COPY --from=kosource /bin/ko /usr/local/bin/ko

# Install Go - quick and dirty
COPY --from=0 /usr/local/go /usr/local/go
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker

RUN apt-get update && apt-get -qqy install --no-install-recommends \
     build-essential ca-certificates curl

ENV PATH="/go/bin:${PATH}:/usr/local/go/bin"

RUN mkdir -p /go/src
ENV GOPATH=/go

RUN gcloud auth configure-docker --quiet

RUN gcloud components install alpha --quiet
COPY --from=istio /usr/local/bin/pilot-agent /usr/local/bin/
COPY --from=istio /usr/local/bin/envoy /usr/local/bin/

# To avoid downloads when building. The builder should be rebuilt on dep changes
COPY go.* ./
RUN go mod download

ENTRYPOINT ["/bin/bash"]
