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
