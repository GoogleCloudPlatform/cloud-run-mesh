
# Must define:
# CLUSTER_NAME
# PROJECT_ID
# CLUSTER_LOCATION

ROOT_DIR?=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OUT?=${ROOT_DIR}/../out/krun

-include .local.mk

PROJECT_ID?=wlhe-cr
export PROJECT_ID


CLUSTER_NAME?=istio
export CLUSTER_NAME

# also mcp-prod - setup for multi-project
CONFIG_PROJECT_ID?=${PROJECT_ID}
# mesh-config-1
CONFIG_CLUSTER_NAME?=${CLUSTER_NAME}

# If the project is part of a multi-project, this is the hub id.
FLEET_ID?=${CONFIG_PROJECT_ID}
export FLEET_ID


# Region where the cloudrun services are running
REGION?=us-central1
export REGION

CLUSTER_LOCATION?=us-central1-c
export CLUSTER_LOCATION


TAG ?= latest
export TAG

# Derived values

REPO?=gcr.io/${PROJECT_ID}

DOCKER_REPO?=gcr.io/${PROJECT_ID}/krun
export DOCKER_REPO

KRUN_IMAGE?=${DOCKER_REPO}:${TAG}

HGATE_IMAGE?=${DOCKER_REPO}/gate:${TAG}

WORKLOAD_NAME?=fortio-cr
WORKLOAD_NAMESPACE?=fortio

CLOUDRUN_SERVICE_ACCOUNT=k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com

ISTIO_HUB?=gcr.io/istio-testing
export ISTIO_HUB
ISTIO_TAG?=latest

# Also possible to use 1.11.2
ISTIO_PROXY_IMAGE?=${ISTIO_HUB}/proxyv2:latest

FORTIO_IMAGE?=${REPO}/fortio-mesh:${TAG}
export FORTIO_IMAGE
export HGATE_IMAGE

# Build krun, fortio, push fortio, deploy to main test cloudrun config
# Expects Istio cluster and in-cluster fortio to be running
all: build build/krun build/fortio push/fortio deploy/fortio

# Build, push, deploy hgate.
all-hgate: build docker/hgate push/hgate deploy/hgate

deploy/hgate:
	mkdir -p ${OUT}/manifests
	echo ${HGATE_IMAGE}
	cat manifests/kustomization-tmpl.yaml | envsubst > ${OUT}/manifests/kustomization.yaml
	cp -a manifests/hgate ${OUT}/manifests
	kubectl apply -k ${OUT}/manifests
	#kubectl apply -f manifests/hgate/
	kubectl rollout restart deployment hgate -n istio-system
	kubectl wait deployments hgate -n istio-system --for=condition=available

# Remove the namespaces and apps, for testing 'clean install'
cluster/clean:
	helm delete -n istio-system istiod
	kubectl delete -k manifests/
	kubectl delete ns istio-system || true
	kubectl delete ns fortio || true
	kubectl delete ns test || true

test:
	go test -timeout 2m -v ./...

# Build all binaries in one step - faster.
# Static build so it works with 'scratch' and not dependent on distro
build:
	mkdir -p ${OUT}/bin/
	mkdir -p ${OUT}/docker-hgate
	mkdir -p ${OUT}/docker-krun
	CGO_ENABLED=0  time  go build -ldflags '-s -w -extldflags "-static"' -o ${OUT}/bin/ ./cmd/hbone/ ./cmd/krun ./cmd/hgate
	ls -l ${OUT}/bin
	mv ${OUT}/bin/krun ${OUT}/docker-krun
	mv ${OUT}/bin/hgate ${OUT}/docker-hgate

# Build and tag krun image locally, will be used in the next phase and for local testing, no push

build/fortio: build/krun
	(cd samples/fortio; GOLDEN_IMAGE=${KRUN_IMAGE} make image)

build/krun: docker/krun


build/hgate: docker/hgate

docker/hgate:
	time docker build ${OUT}/docker-hgate -f tools/docker/Dockerfile.meshcon -t ${HGATE_IMAGE}

docker/krun:
	time docker build ${OUT}/docker-krun -f tools/docker/Dockerfile.golden -t ${KRUN_IMAGE}

test/e2e: CR_URL=$(shell gcloud run services describe ${WORKLOAD_NAME} --region ${REGION} --project ${PROJECT_ID} --format="value(status.address.url)")
test/e2e:
	curl  -v  ${CR_URL}/fortio/fetch2/?url=http%3A%2F%2Ffortio.fortio.svc%3A8080%2Fecho
	curl  -v  ${CR_URL}/fortio/fetch2/?url=http%3A%2F%2Ffortio.fortio-mcp.svc%3A8080%2Fecho
	curl  -v  ${CR_URL}/fortio/fetch2/?url=http%3A%2F%2Fhttpbin.httpbin.svc%3A8000%2Fheaders
    #curl  ${CR_URL}/fortio/fetch2/?url=http%3A%2F%2Flocalhost%3A15000%2Fconfig_dump

#### Pushing images

push/hgate:
	docker push ${HGATE_IMAGE}

push/krun:
	docker push ${KRUN_IMAGE}

push/fortio:
	(cd samples/fortio; make push)

push/builder:
	docker push gcr.io/${PROJECT_ID}/crm-builder:latest

#### Deploy

deploy/fortio:
	(cd samples/fortio; make deploy setup-sni)

deploy/fortio-auth:
	gcloud alpha run deploy fortio-auth \
    		  --execution-environment=gen2 \
    		  --platform managed --project ${PROJECT_ID} --region ${REGION} \
    		  --service-account=${CLOUDRUN_SERVICE_ACCOUNT} \
              --vpc-connector projects/${PROJECT_ID}/locations/${REGION}/connectors/serverlesscon \
             \
             --use-http2 \
             --port 15009 \
             \
             --image ${FORTIO_IMAGE} \

deploy/fortio-debug:
	gcloud alpha run deploy fortio-debug -q \
    		  --execution-environment=gen2 \
    		  --platform managed --project ${PROJECT_ID} --region ${REGION} \
    		  --service-account=${CLOUDRUN_SERVICE_ACCOUNT} \
              --vpc-connector projects/${PROJECT_ID}/locations/${REGION}/connectors/serverlesscon \
             \
             --set-env-vars="^.^ENVOY_LOG_LEVEL=debug,config:warn,main:warn,upstream:warn" \
             \
             --use-http2 \
             --port 15009 \
             \
             --image ${FORTIO_IMAGE} \


deploy/fortio-asm:
    # OSS/ASM with Istiod exposed in Gateway, with ACME certs
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAME=fortio-crasm \
		FORTIO_DEPLOY_EXTRA="--set-env-vars MESH_TENANT=-" \
		make deploy)

logs:
	(cd samples/fortio; make logs)

# Send traffic from pod to cloudrun
pod2cr: POD=$(shell kubectl --namespace=fortio get -l app=fortio pod -o=jsonpath='{.items[0].metadata.name}')
pod2cr:
	kubectl exec -n fortio ${POD} -- fortio load ${FORTIO_LOAD_ARG} fortio-cr:8080/echo

################# Testing / local dev #################
# For testing/dev in local docker

docker/_run: ADC?=${HOME}/.config/gcloud/legacy_credentials/$(shell gcloud config get-value core/account)/adc.json
docker/_run:
	docker run -it --rm \
		-e PROJECT_ID=${PROJECT_ID} \
		-e GOOGLE_APPLICATION_CREDENTIALS=/var/run/secrets/google/google.json \
		-v ${ADC}:/var/run/secrets/google/google.json:ro \
		${_RUN_EXTRA} \
		${_RUN_IMAGE} \
	   /bin/bash

# 		-e CLUSTER_NAME=${CLUSTER_NAME} \
  #		-e CLUSTER_LOCATION=${CLUSTER_LOCATION} \


# Run krun in a docker image, get a shell. Will use MCP.
docker/run-mcp:
	_RUN_IMAGE=${KRUN_IMAGE} $(MAKE) docker/_run

# Run in local docker, using ADC for auth and an explicit XDS address
docker/run-xds-adc:
	_RUN_EXTRA="-e XDS_ADDR=istiod.wlhe.i.webinf.info:443"   _RUN_IMAGE=${KRUN_IMAGE} $(MAKE) docker/_run

# Run hgate in a local docker container, for testing. Will connect to the cluster.
#
# ISTIO_META_INTERCEPTION_MODE disable interception (not using it).
# DISABLE_ENVOY also disables envoy - only using the cert part in istio-agent
docker/run-hgate:
	_RUN_EXTRA="-e DISABLE_ENVOY=true -e ISTIO_META_INTERCEPTION_MODE=NONE -p 15441:15441" \
 	_RUN_IMAGE=${HGATE_IMAGE}  \
 		$(MAKE) docker/_run

# Run without ADC, only kubeconfig
docker/run-kubeconfig:
	docker run  -e KUBECONFIG=/var/run/kubeconfig -v ${HOME}/.kube/config:/var/run/kubeconfig:ro -it  \
		${KRUN_IMAGE}  /bin/bash

docker/build-run-fortio: build/krun build/fortio
	_RUN_IMAGE=${FORTIO_IMAGE} $(MAKE) docker/_run

docker/run-fortio:
	_RUN_IMAGE=${FORTIO_IMAGE} $(MAKE) docker/_run

################## Setup/preparation

## Cluster setup for samples and testing
deploy/k8s-fortio:
	kubectl apply -f samples/fortio/in-cluster.yaml

# Update base images, for build/krun ( local build )
pull:
	docker pull gcr.io/istio-testing/proxyv2:latest

# Get deps
deps:
	curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
	chmod +x kubectl
	# TODO: helm, gcrane

# Used for the target installing in-cluster istio, not required when testing with MCP
#ISTIO_CHARTS?=../istio/manifests/charts/istio-control/istio-discovery

ISTIO_CHARTS?=istio/istiod
#REV?=v1-11
CHART_VERSION=--devel

helm/addcharts:
	helm repo add istio https://istio-release.storage.googleapis.com/charts
	helm repo update

deploy/istio-base:
	kubectl create namespace istio-system | true
	helm upgrade --install istio-base istio/base -n istio-system ${CHART_VERSION} | true

# Default install of istiod, with a number of options set for interop with ASM and MCP.
#
# TODO: add docs on how to upgrade an existing istio, explain the config.
#
# To install a revisioned istio, replace "istiod" with "istiod-REV and add --set revision=${REV}
#
# Note that trustDomain is set to the value used by ASM - on GKE this is important since it allows getting access
# tokens. If using istio-ca ( standard istio ), OSS_ISTIO=true must be set when starting the app, to get the right
# type of token. TODO: trust domain should be included in the mesh-env and used from there.
deploy/istiod:
	helm upgrade --install \
 		-n istio-system \
 		istiod \
        ${ISTIO_CHARTS} \
        ${CHART_VERSION} \
        ${ISTIOD_EXTRA} \
        --set global.hub=${ISTIO_HUB} \
        --set global.tag=${ISTIO_TAG} \
		--set telemetry.enabled=true \
		--set global.sds.token.aud="${CONFIG_PROJECT_ID}.svc.id.goog" \
        --set meshConfig.trustDomain="${CONFIG_PROJECT_ID}.svc.id.goog" \
        \
		--set meshConfig.proxyHttpPort=15007 \
        --set meshConfig.accessLogFile=/dev/stdout \
        \
        --set pilot.replicaCount=1 \
        --set pilot.autoscaleEnabled=false \
        \
		--set pilot.env.TOKEN_AUDIENCES="${CONFIG_PROJECT_ID}.svc.id.goog\,istio-ca" \
        --set pilot.env.ISTIO_MULTIROOT_MESH=true \
        --set pilot.env.PILOT_ENABLE_WORKLOAD_ENTRY_AUTOREGISTRATION=true \
		--set pilot.env.PILOT_ENABLE_WORKLOAD_ENTRY_HEALTHCHECKS=true

default-ns-istio-system:
	 kubectl config set-context --current --namespace=istio-system

# Special config for GKE autopilot - disable mutating-webhook related functions
# For extra logs, add --set global.logging.level=all:debug
deploy/istiod-autopilot:
	ISTIOD_EXTRA="--set global.operatorManageWebhooks=true --set pilot.env.PRIORITIZED_LEADER_ELECTION=false --set pilot.env.INJECTION_WEBHOOK_CONFIG_NAME='' " \
		$(MAKE) deploy/istiod

############ Canary (stability/e2e) ##############

# Canary will deploy a 'canary' version of a cloudrun instance using the current golden image, and verify it works
# Used in GCB, where the images are built with Kaniko
e2e: canary/deploy canary/test

# Build, push and run e2e
e2e/all: build docker/krun push/krun docker/hgate push/hgate push/fortio canary


canary/deploy: canary/deploy-mcp canary/deploy-mcp2 canary/deploy-asm canary/deploy-auth

canary/deploy-mcp:
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAME=fortio-crmcp  \
    	make deploy setup-sni)

# Deploy in another cluster
canary/deploy-mcp2:
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAME=fortio-asm-cr CLUSTER_NAME=asm-cr CLUSTER_LOCATION=us-central1-c \
		FORTIO_DEPLOY_EXTRA="--set-env-vars CLUSTER_NAME=${CLUSTER_NAME}" \
    	make deploy setup-sni)

canary/deploy-asm:
    # OSS/ASM with Istiod exposed in Gateway, with ACME certs
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAME=fortio-istio \
		FORTIO_DEPLOY_EXTRA="--set-env-vars MESH_TENANT=-" \
		make deploy setup-sni)

# Init the second project. We'll use 'test' namespace
# Once this is done, the workload project k8s-NAMESPACE GSA will be able to use the mesh
# in the config cluster.
mp/workload-project-namespace-init:
	# Init the GSA and bindings for CR in MP_PROJECT_ID to use the config clusters.
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAMESPACE=test \
		CONFIG_PROJECT_ID=${CONFIG_PROJECT_ID} \
		make setup-gsa) || true

	# Allow the GSA in the workload project access to the namespace in config cluster.
	# The KSA is in the config cluster - and equivalent with the GSA in the config project.
	# The GSA in the workload project is only allowed to act as the KSA/GSA in config project, no additional permissions
	# on the mesh or K8S. It can have additional permissions used by the app, when using metadata server tokens.
	# Mesh interactions are using the KSA
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAMESPACE=test \
		CONFIG_PROJECT_ID=${CONFIG_PROJECT_ID}  \
		CLUSTER_NAME=${CONFIG_CLUSTER_NAME} CLUSTER_LOCATION=${CLUSTER_LOCATION} \
		make setup-rbac)

# TODO: serverless connector access or multi-network ?
mp/vpc:
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAMESPACE=test \
		CONFIG_PROJECT_ID=${CONFIG_PROJECT_ID}  \
		CLUSTER_NAME=${CONFIG_CLUSTER_NAME} \
		make vpc-access)


# Multiproject test - deploy the workload in a second project (costin-asm1 for the CI)
mp/deploy:
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAMESPACE=test \
		CONFIG_PROJECT_ID=${CONFIG_PROJECT_ID}  \
		CLUSTER_NAME=${CONFIG_CLUSTER_NAME} \
		FORTIO_DEPLOY_EXTRA="" \
		make deploy-auth)


# Alternative, using real cert:	XDS_ADDR=istiod.wlhe.i.webinf.info:443" \

canary/deploy-auth:
	(cd samples/fortio; REGION=${REGION} WORKLOAD_NAME=fortio-istio-auth \
		make deploy-auth)

# Example: MCP_URL=https://fortio-asm-cr-icq63pqnqq-uc.a.run.app
canary/test: CR_MCP_URL=$(shell gcloud run services describe fortio-crmcp --region ${REGION} --project ${PROJECT_ID} --format="value(status.address.url)")
canary/test: CR_ASM_URL=$(shell gcloud run services describe fortio-istio --region ${REGION} --project ${PROJECT_ID} --format="value(status.address.url)")
canary/test:
	curl  -v  ${CR_MCP_URL}/fortio/fetch2/?url=http%3A%2F%2Ffortio.fortio.svc%3A8080%2Fecho
	curl  -v ${CR_ASM_URL}/fortio/fetch2/?url=http%3A%2F%2Ffortio.fortio.svc%3A8080%2Fecho
	# Dump the envoy config, for reference/debugging
	curl -v  ${CR_MCP_URL}/fortio/fetch2/?url=http%3A%2F%2Flocalhost%3A15000%2Fconfig_dump

##### Logs

logs/fortio-mcp:
	(cd samples/fortio; WORKLOAD_NAME=fortio-mcp make logs)

# Show MCP logs
logs-mcp:
	gcloud --project ${CONFIG_PROJECT_ID} logging read \
    	   --format "csv(textPayload,jsonPayload.message)" \
    		--freshness 1h \
     		'resource.type="istio_control_plane"'

#### CAS setup

# Setup CAS and create the root CA
cas/setup:
	gcloud privateca pools create --project "${CONFIG_PROJECT_ID}" mesh --tier devops --location ${REGION}

	# Creates projects/PROJECT_ID/locations/LOCATION/caPools/mesh/certificateAuthorities/mesh-selfsigned
	# May want to use O=MESH_ID, for multi-project.
	# Google managed
	gcloud privateca roots create --project "${CONFIG_PROJECT_ID}" mesh-selfsigned --pool mesh --location ${REGION} \
		--auto-enable \
        --subject "CN=${PROJECT_ID}, O=${FLEET_ID}"

	gcloud privateca pools --project "${CONFIG_PROJECT_ID}" add-iam-policy-binding mesh \
        --project "${CONFIG_PROJECT_ID}" \
        --location "${REGION}" \
        --member "group:${FLEET_ID}.svc.id.goog:/allAuthenticatedUsers/" \
        --role "roles/privateca.workloadCertificateRequester"

# Setup the config cluster to use workload certificates.
cas/setup-cluster: CONFIG_PROJNUM=$(shell gcloud projects describe ${CONFIG_PROJECT_ID} --format="value(projectNumber)")
cas/setup-cluster:
	gcloud container clusters update ${CLUSTER_NAME} --project "${CONFIG_PROJECT_ID}" --region ${CLUSTER_LOCATION} --enable-mesh-certificates
	gcloud privateca pools add-iam-policy-binding --project "${CONFIG_PROJECT_ID}" mesh \
	  --location ${REGION} \
	  --role roles/privateca.certificateManager \
	  --member="serviceAccount:service-${CONFIG_PROJNUM}@container-engine-robot.iam.gserviceaccount.com"

cas/setup-k8s:
	cat manifests/cas-template.yaml | envsubst | kubectl apply -f -

#gcloud privateca pools add-iam-policy-binding istio \
#   --role=roles/privateca.workloadCertificateRequester
# --member="serviceAccount:service-601426346923@gcp-sa-meshdataplane.iam.gserviceaccount.com"
#--project wlhe-cr --location=us-central1



# Requires the pyca library. Alternative: certtool
cas/cert:
	gcloud privateca certificates create \
        --issuer-pool mesh --issuer-location ${REGION} \
        --subject "CN=${PROJECT_ID},O=${PROJECT_ID}" \
        --generate-key \
        --key-output-file key.pem \
        --cert-output-file cert.pem

# WIP - needs to wait, test - this seems to be the sequence needed to import
cas/import:
	gcloud kms keyrings create istio \
    	--location ${REGION}
	gcloud kms keys list --keyring istio --location ${REGION}

	gcloud kms keys create istio-citadel \
      --location ${REGION} \
      --keyring istio \
      --purpose purpose \
      --skip-initial-version-creation \
      --import-only

	gcloud kms import-jobs create import-job \
      --location ${REGION} \
      --keyring istio \
      --import-method rsa-oaep-3072-sha1-aes-256 \
      --protection-level software # or 'hsm'

    # Must be ACTIVE
	gcloud kms import-jobs describe import-job \
       --location ${REGION} \
       --keyring istio \
       --format="value(state)"

    # PEM, PKCS#8
	openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER \
        -in ${OUT}/key.pem \
        -out ${OUT}/key.der

	gcloud kms keys versions import \
      --import-job $${import-job} \
      --location ${REGION} \
      --keyring istio \
      --key istio-citadel \
      --algorithm algorithm-name \
      --target-key-file ${OUT}/key.der

	# projects/example-project-98765/locations/us-central1/keyRings/example-ring/cryptoKeys/example-key
	gcloud privateca roots create istio-citdel --pool istio \
        --subject "CN=Common Name, O=Organization Name" \
        --kms-key-version kms-resource-name

gcp/services:
	gcloud services enable --project ${CONFIG_PROJECT_ID} \
        container.googleapis.com \
        cloudresourcemanager.googleapis.com \
        compute.googleapis.com \
        trafficdirector.googleapis.com \
        networkservices.googleapis.com \
        networksecurity.googleapis.com \
        privateca.googleapis.com \
        gkehub.googleapis.com

##### GCB related targets

# Create the builder docker image, used in GCB
gcb/builder:
	gcloud builds --project ${PROJECT_ID} submit . --config=tools/builder/cloudbuild.yaml

# Use cloud-build-local.
# I didn't find a way to get Kaniko to work with cloud-build-local - complaining about authorization,
# but useful for checking syntax errors in the file.
gcb/local:
	mkdir -p ${OUT}/gcb-local
	cloud-build-local --dryrun=false --push=true --write-workspace=${OUT}/gcb-local  \
		--substitutions=_TAG=local \
		--config=cloudbuild.yaml .

gcb/local-builder:
	mkdir -p ${OUT}/gcb-local-builder
	cloud-build-local --dryrun=false --push=true --write-workspace=${OUT}/gcb-local-builder  \
		--config=tools/builder/cloudbuild.yaml .

build/docker-builder:
	time docker build . -f tools/builder/Dockerfile -t gcr.io/${PROJECT_ID}/crm-builder

# Submit a build request to GCB manually.
# Useful for checking the changes without creating a PR or branch.
gcb/submit:
	gcloud builds --project ${PROJECT_ID}  submit . --substitutions=_TAG=localdev

# Create a tagged release, promoting current main
release/tag:
	gcrane tag gcr.io/wlhe-cr/krun:main ${REL_TAG}
	gcrane tag gcr.io/wlhe-cr/krun/gate:main ${REL_TAG}
	gcrane tag gcr.io/wlhe-cr/fortio-mesh:main ${REL_TAG}


# Promote 'main' branch to latest
release/latest:
	gcrane tag gcr.io/wlhe-cr/krun:main latest
	gcrane tag gcr.io/wlhe-cr/krun/gate:main latest
	gcrane tag gcr.io/wlhe-cr/fortio-mesh:main latest

