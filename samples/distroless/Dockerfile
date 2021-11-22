ARG BASE=gcr.io/wlhe-cr/krun:main-distroless

FROM istio/app:1.12.0 as app
FROM gcr.io/distroless/base:debug as debug

FROM ${BASE} as istio_base
#FROM gcr.io/wlhe-cr/krun:main as istio_base

COPY --from=app /usr/local/bin/client /usr/local/bin/server /usr/local/bin/
COPY --from=app /cert.* /

# Add debug
COPY --from=debug /busybox/ /busybox

ENV PATH=${PATH}:/busybox
ENV ISTIO_META_ISTIO_VERSION=${ISTIO_META_ISTIO_VERSION}-cloudrun

USER 0
CMD ["/usr/local/bin/server"]
