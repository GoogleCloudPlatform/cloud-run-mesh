## Same base as Istio proxyless
FROM gcr.io/istio-testing/proxyv2:latest-distroless as istio_base


# The following section is used as base image if BASE_DISTRIBUTION=distroless
# This image is a custom built debian11 distroless image with multiarchitecture support.
# It is built on the base distroless image, with iptables binary and libraries added
# The source can be found at https://github.com/istio/distroless/tree/iptables
# This version is from commit 20b20ec36f4621830ff0bfdec519577074df47ca.
#FROM gcr.io/istio-release/iptables@sha256:875a2ec94a816dcb3da35fb559ac63cfe0345018a82b396491eb0e0dbbc15f18 as distroless

# Same base as istio.io/istio/docker/Dockerfile.distroless
# You can use any other base file - as long as the libc version is compatible with debian11
# FROM gcr.io/distroless/static-debian11@sha256:1061399c202961ab567994c1bd42327bccd6380a345dcf88bf9ad7d5c8e29571 as distroless_source

# Files added in istio.io/istio/docker/Dockerfile.distroless, via 'echo' into passwd/group
COPY --from=istio_base /home/etc/passwd /etc/passwd
COPY --from=istio_base /home/etc/group /etc/group
COPY --from=istio_base /home/nonroot /home/nonroot

# Keep in sync with istio.io/istio/pilot/docker/Dockerfile.proxyv2
WORKDIR /
COPY --from=istio_base /var/lib/istio/envoy/envoy_bootstrap_tmpl.json /var/lib/istio/envoy/envoy_bootstrap_tmpl.json
COPY --from=istio_base /var/lib/istio/envoy/gcp_envoy_bootstrap_tmpl.json /var/lib/istio/envoy/gcp_envoy_bootstrap_tmpl.json
COPY --from=istio_base /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=istio_base /usr/local/bin/pilot-agent /usr/local/bin/pilot-agent

  #             DISTRO_PACKAGES[arch]["_debian11"]["iptables"],
  #            DISTRO_PACKAGES[arch]["_debian11"]["libip4tc2"],
  #            DISTRO_PACKAGES[arch]["_debian11"]["libip6tc2"],
  #            DISTRO_PACKAGES[arch]["_debian11"]["libxtables12"],
  #            DISTRO_PACKAGES[arch]["_debian11"]["libnfnetlink0"],
  #            DISTRO_PACKAGES[arch]["_debian11"]["libnetfilter-conntrack3"],
  #            DISTRO_PACKAGES[arch]["_debian11"]["libmnl0"],
COPY --from=istio_base /usr/sbin/iptables-restore /usr/sbin/iptables-restore
COPY --from=istio_base /usr/lib/x86_64-linux-gnu/xtables /usr/lib/x86_64-linux-gnu/
COPY --from=istio_base /usr/sbin/xtables-legacy-multi
./usr/lib/x86_64-linux-gnu/libip4tc.so.2.0.0
./usr/lib/x86_64-linux-gnu/libip6tc.so.2.0.0
./usr/lib/x86_64-linux-gnu/libxtables.so.12.4.0
./usr/lib/x86_64-linux-gnu/libnfnetlink.so.0.2.0
./usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so.3.7.0
./usr/lib/x86_64-linux-gnu/libmnl.so.0.2.0


# TODO: not sure how to set env variable here...
ENV ISTIO_META_ISTIO_PROXY_SHA ${ISTIO_META_ISTIO_PROXY_SHA}
ENV ISTIO_META_ISTIO_VERSION ${ISTIO_META_ISTIO_VERSION}

COPY --from=istio_base stats-filter.wasm /etc/istio/extensions/stats-filter.wasm
COPY --from=istio_base stats-filter.compiled.wasm /etc/istio/extensions/stats-filter.compiled.wasm
COPY --from=istio_base metadata-exchange-filter.wasm /etc/istio/extensions/metadata-exchange-filter.wasm
COPY --from=istio_base metadata-exchange-filter.compiled.wasm /etc/istio/extensions/metadata-exchange-filter.compiled.wasm

# The pilot-agent will bootstrap Envoy.
ENTRYPOINT ["/usr/local/bin/pilot-agent"]

