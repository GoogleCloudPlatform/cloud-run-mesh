# Quick notes on using OSS Istio

The install steps can be found in the Makefile on this project, and are based on a clean install.

For existing Istio installs, see the options used in the helm install and make sure they are applied to your current 
install.

```shell

# Add the istio charts
make helm/addcharts

# Deploy CRDs
make deploy/istio-base

# Deploy Istiod
make deploy/istiod
#or for GKE autopilot:
#make deploy/istiod-autopilot

# Deploy Mesh Connector Gateway
make deploy/hgate

```
