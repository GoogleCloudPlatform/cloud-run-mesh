Sample for running Fortio with Istio sidecar in CloudRun.

The Dockerfile uses the golden image, and adds Fortio binaries.

Makefile includes examples for configuring the service account mapping and deploying the CloudRun service.

It also includes few debug targets - ssh, logs, config_dump
