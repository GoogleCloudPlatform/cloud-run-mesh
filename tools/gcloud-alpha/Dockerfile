# Specialized builder - should include all deps for running the tests
# Based on alpine - both for size and to validate it compiles with alpine/musl.

FROM golang:alpine AS go

# At least this version, for executuin-environment.
FROM gcr.io/google.com/cloudsdktool/cloud-sdk:353.0.0-alpine

# Currently required for --execution-environment
RUN gcloud components install -q alpha kubectl

RUN apk update && apk add gcc bash musl-dev openssl-dev ca-certificates make && update-ca-certificates

COPY --from=go /usr/local/go /usr/local/

ENV PATH=$PATH:/usr/local/go/bin

ENTRYPOINT ["/bin/sh"]
