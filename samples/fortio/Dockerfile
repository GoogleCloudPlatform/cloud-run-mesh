# Sample dockerfile for using a 'golden' image including envoy, mesh agents and adding a user application
# (fortio).


# The base image is auto-build on github. You can also build your own base image from krun or
# your own fork. The image is based on Istio proxyv2 image, with krun added.
# Alternatively, any Debian/Ubuntu/RedHat image with libraries compatible with envoy can be used, adding
# pilot-agent, envoy from istio-proxy and krun from this repo.
ARG BASE=gcr.io/wlhe-cr/krun:main

# App code - can be an already built container, or the dockerfiel building.
FROM fortio/fortio:latest AS app

# Base is the Istio proxy image, including envoy, agent, krun
FROM ${BASE}

# Add the application and dependent files to the image
#COPY --from=fortio /usr/share/fortio /usr/share/fortio
COPY --from=app /usr/bin/fortio /usr/bin/fortio

# Make sure the entrypoint is set to krun. Krun is built with 'ko', which uses a specific dir.
ENTRYPOINT ["/usr/local/bin/krun"]

# Default ports:
ENV PORT_grpc=8079
ENV PORT_http=8080
ENV PORT_tcp-echo=8079

# Normal application command.
# Fortio supports HTTP and TCP proxy as well
CMD ["/usr/bin/fortio", "server"]
