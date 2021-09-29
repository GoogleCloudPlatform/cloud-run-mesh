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

# Specialized builder - should include all deps for running the tests
# Based on alpine - both for size and to validate it compiles with alpine/musl.

FROM golang:alpine AS go

# At least this version, for executuin-environment.
FROM gcr.io/google.com/cloudsdktool/cloud-sdk:353.0.0-alpine

# Currently required for --execution-environment
RUN gcloud components install -q alpha kubectl

RUN apk update && apk add gcc bash musl-dev openssl-dev ca-certificates make gettext && update-ca-certificates

COPY --from=go /usr/local/go /usr/local/

ENV PATH=$PATH:/usr/local/go/bin

ENTRYPOINT ["/bin/sh"]
