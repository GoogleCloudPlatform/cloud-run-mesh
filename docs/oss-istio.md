# Quick notes on using OSS Istio

The install steps can be found in the Makefile on this project, and are based on a clean install.

For existing Istio installs, see the options used in the helm install and make sure they are applied to your current 
install.

```shell

# Add the istio charts - make helm/addcharts
helm repo add istio https://istio-release.storage.googleapis.com/charts
helm repo update

# Deploy Istio CRDs - make deploy/istio-base
CHART_VERSION=--devel
kubectl create namespace istio-system 
helm upgrade --install istio-base istio/base -n istio-system ${CHART_VERSION} 

# Deploy Istiod - make deploy/istiod
	helm upgrade --install \
 		-n istio-system \
 		istiod \
        istio/istiod \
        ${CHART_VERSION} \
		--set telemetry.enabled=true \
		--set global.sds.token.aud="${CONFIG_PROJECT_ID}.svc.id.goog" \
        --set meshConfig.trustDomain="${CONFIG_PROJECT_ID}.svc.id.goog" \
		--set pilot.env.TOKEN_AUDIENCES="${CONFIG_PROJECT_ID}.svc.id.goog\,istio-ca" \
        --set pilot.env.ISTIO_MULTIROOT_MESH=true 

#or for GKE autopilot:
#make deploy/istiod-autopilot

# Deploy Mesh Connector Gateway
make deploy/hgate

```
If all goes well, check that the mesh-env was created: `kubectl -n istio-system get cm mesh-env -o yaml`
This will be used by workloads in CloudRun/Docker and other environments where pod injection is not used, and 
should include the typical values that K8S injections will add to the pods.
