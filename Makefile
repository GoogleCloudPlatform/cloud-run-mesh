
# Must define:
# CLUSTER_NAME
# PROJECT_ID
# CLUSTER_LOCATION

ROOT_DIR?=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OUT?=${ROOT_DIR}/../out/krun

-include .local.mk

PROJECT_ID?=wlhe-cr
export PROJECT_ID

# Region where the cloudrun services are running
REGION?=us-central1
export REGION

CLUSTER_LOCATION?=us-central1-c
export CLUSTER_LOCATION


CLUSTER_NAME?=istio
export CLUSTER_NAME

TAG ?= latest

# Derived values

DOCKER_REPO?=gcr.io/${PROJECT_ID}/krun
export DOCKER_REPO

KRUN_IMAGE?=${DOCKER_REPO}:latest

HGATE_IMAGE?=${DOCKER_REPO}/gate:latest

WORKLOAD_NAME?=fortio-cr
WORKLOAD_NAMESPACE?=fortio

CLOUDRUN_SERVICE_ACCOUNT=k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com

# Also possible to use 1.11.2
ISTIO_PROXY_IMAGE?=gcr.io/istio-testing/proxyv2:latest

FORTIO_IMAGE?=gcr.io/${PROJECT_ID}/fortio-mesh:latest
export FORTIO_IMAGE

# Build krun, fortio, push fortio, deploy to main test cloudrun config
# Expects Istio cluster and in-cluster fortio to be running
all: build/krun push/fortio deploy/fortio

# Build, push, deploy hgate.
all-hgate: build docker/hgate push/hgate deploy/hgate

deploy/hgate:
	kubectl apply -f manifests/hgate/
	kubectl rollout restart deployment hgate -n istio-system
	kubectl wait deployments hgate -n istio-system --for=condition=available


test:
	go test -timeout 2m -v ./...

# Build all binaries in one step - faster.
# Static build so it works with 'scratch' and not dependent on distro
build:
	CGO_ENABLED=0  time  go build -ldflags '-s -w -extldflags "-static"' -o ${OUT}/ ./cmd/hbone/ ./cmd/krun ./cmd/hgate
	ls -l ${OUT}

# Build and tag krun image locally, will be used in the next phase and for local testing, no push

build/fortio: build/krun
	(cd samples/fortio; GOLDEN_IMAGE=${KRUN_IMAGE} make image)

build/krun: docker/krun


build/hgate: docker/hgate

docker/hgate:
	time docker build ${OUT}/ -f tools/docker/Dockerfile.meshcon -t ${HGATE_IMAGE}

docker/krun:
	time docker build ${OUT}/ -f tools/docker/Dockerfile.golden -t ${KRUN_IMAGE}

# Same thing, using docker build - slower
build/docker-krun:
	docker build . -t ${KRUN_IMAGE}

# Same thing with docker
build/docker-hgate:
	time docker build . -f meshcon/Dockerfile -t ${HGATE_IMAGE}


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

push/fortio: build/fortio
	(cd samples/fortio; make push)

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

ssh:
	(cd samples/fortio; make ssh)

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


# Default install of istiod, with a number of options set for interop with ASM and MCP.
#
# TODO: add docs on how to upgrade an existing istio, explain the config.
#
# To install a revisioned istio, replace "istiod" with "istiod-REV and add --set revision=${REV}
deploy/istiod:
	kubectl create namespace istio-system | true
	helm install istio-base istio/base -n istio-system ${CHART_VERSION} | true
	helm upgrade --install \
 		-n istio-system \
 		istiod \
        ${ISTIO_CHARTS} \
        ${CHART_VERSION} \
		--set telemetry.enabled=true \
		--set global.sds.token.aud="${PROJECT_ID}.svc.id.goog" \
        --set meshConfig.trustDomain="${PROJECT_ID}.svc.id.goog" \
        \
		--set meshConfig.proxyHttpPort=15007 \
        --set meshConfig.accessLogFile=/dev/stdout \
        \
        --set pilot.replicaCount=1 \
        --set pilot.autoscaleEnabled=false \
        \
		--set pilot.env.TOKEN_AUDIENCES="${PROJECT_ID}.svc.id.goog\,istio-ca" \
        --set pilot.env.ISTIO_MULTIROOT_MESH=true \
        --set pilot.env.PILOT_ENABLE_WORKLOAD_ENTRY_AUTOREGISTRATION=true \
		--set pilot.env.PILOT_ENABLE_WORKLOAD_ENTRY_HEALTHCHECKS=true

############ Canary (stability/e2e) ##############

canary/all: push/fortio canary

# Canary will deploy a 'canary' version of a cloudrun instance using the current golden image, and verify it works
# Used in GCB, where the images are built with Kaniko
canary: canary/deploy canary/test

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

config_dump:
	@(cd samples/fortio;  make -s config_dump_ssh)
##### GCB related targets

# Create the builder docker image, used in GCB
gcb/builder:
	gcloud builds --project ${PROJECT_ID} submit . --config=tools/gcb/cloudbuild.yaml

gcb/builder-gcloud:
	gcloud builds --project ${PROJECT_ID} submit . --config=tools/gcloud-alpha/cloudbuild.yaml

gcb/local:
	mkdir -p ${OUT}/gcb-local
	cloud-build-local --dryrun=false --push=true --write-workspace=${OUT}/gcb-local  --substitutions=BRANCH_NAME=local,COMMIT_SHA=local --config=cloudbuild.yaml .

gcb/build-hgate:
	gcloud builds --project ${PROJECT_ID} submit  --config=cmd/gate/cloudbuild.yaml .

gcb/build:
	gcloud builds --project ${PROJECT_ID} submit .


logs-mcp:
	gcloud --project ${PROJECT_ID} logging read \
    	   --format "csv(textPayload,jsonPayload.message)" \
    		--freshness 1h \
     		'resource.type="istio_control_plane"'
