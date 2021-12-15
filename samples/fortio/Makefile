# Local settings - create a config file to avoid passing parms on each
# call.
-include .local.mk
-include ../../.local.mk

# Defaults, using the internal test cluster - must be overriden

# GKE cluster used
PROJECT_ID?=wlhe-cr
CLUSTER_LOCATION?=us-central1-c
CLUSTER_NAME?=istio

# Region where CR will be deployed
REGION?=us-central1

# By default, cloudrun will run in same project as the config clusters.
CONFIG_PROJECT_ID?=${PROJECT_ID}
export CONFIG_PROJECT_ID

K8S_CONTEXT?=gke_${CONFIG_PROJECT_ID}_${CLUSTER_LOCATION}_${CLUSTER_NAME}


################ derived values

# Where to store the images
REPO?=gcr.io/${PROJECT_ID}

# Base image, including istio-proxy, envoy, starter. Built by the CI/CD on the test project.
GOLDEN_IMAGE?=gcr.io/wlhe-cr/krun:main

# A pre-build version exists in gcr.io/wlhe-cr/fortio-mesh:main
FORTIO_IMAGE?=${REPO}/fortio-mesh:latest

# Namespace to attach to.
WORKLOAD_NAMESPACE?=fortio

CLOUDRUN_SERVICE_ACCOUNT=k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com

export CLOUDRUN_SERVICE_ACCOUNT
export WORKLOAD_NAMESPACE
export PROJECT_ID


# Name of the workload. For CloudRun, this is also the default 'canonical service' and the name of the associated
# service entry/service.
WORKLOAD_NAME?=fortio-cr
export WORKLOAD_NAME

SERVICE?=${WORKLOAD_NAME}

# Create fortio+proxy image, deploy to CloudRun
all: image push deploy setup-service

# Run first, to create the permissions
setup: setup-gsa setup-rbac


# Build the image using the proxy as base
image:
	docker build --build-arg=BASE=${GOLDEN_IMAGE} -t ${FORTIO_IMAGE} ${DOCKER_BUILD_ARGS} .

push:
	docker push ${FORTIO_IMAGE}

# Useful for debugging:
# Note: ^.^ changes the separator for env vars from : to .
#  		 --set-env-vars="^.^ENVOY_LOG_LEVEL=debug,config:warn,main:warn,upstream:warn" \
#  		 --set-env-vars="XDS_AGENT_DEBUG=googleca:debug" \

# Deploy to cloudrun
# Adding XDS_ADDR=READ_DOMAIN:443 will skip looking up for MCP configmap and use that address instead.
deploy:
	gcloud alpha run deploy ${SERVICE} \
		  --execution-environment=gen2 \
		  --platform managed --project ${PROJECT_ID} --region ${REGION} \
		  --service-account=${CLOUDRUN_SERVICE_ACCOUNT} \
          --vpc-connector projects/${CONFIG_PROJECT_ID}/locations/${REGION}/connectors/serverlesscon \
         \
         --allow-unauthenticated \
         \
         --use-http2 \
         --port 15009 \
         \
         --concurrency 10 --timeout 900 --cpu 1 --memory 1G \
         --min-instances 1 \
         \
		--image ${FORTIO_IMAGE} \
		\
		   --set-env-vars="MESH=//container.googleapis.com/projects/${CONFIG_PROJECT_ID}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}" \
  		  ${FORTIO_DEPLOY_EXTRA} \
		 --set-env-vars="DEPLOY=$(shell date +%y%m%d-%H%M)"


# No longer used:
#		   --set-env-vars="CLUSTER_NAME=${CLUSTER_NAME}" \
#		   --set-env-vars="CLUSTER_LOCATION=${CLUSTER_LOCATION}" \
#		   --set-env-vars="PROJECT_ID=${CONFIG_PROJECT_ID}" \

# This is the barebone deploy, with auth enabled
deploy-auth:
	gcloud alpha run deploy ${SERVICE}-auth \
		  --execution-environment=gen2 \
		  --platform managed --project ${PROJECT_ID} --region ${REGION} \
		  --service-account=${CLOUDRUN_SERVICE_ACCOUNT} \
          --vpc-connector projects/${CONFIG_PROJECT_ID}/locations/${REGION}/connectors/serverlesscon \
         \
         --use-http2 \
         --port 15009 \
         \
		--no-allow-unauthenticated \
         \
         --image ${FORTIO_IMAGE} \
  		  --set-env-vars=MESH=gke://${CONFIG_PROJECT_ID} \
  		 ${FORTIO_DEPLOY_EXTRA}


# Port 14009 for using envoy for ingress
# Port 8080 for going directly to the app
# Port 15009 for using KRun and 'native' hbone.

# Get latest golden image
pull:
	docker pull ${GOLDEN_IMAGE}


###########################################

# Create a Google Service Account (GSA) associated with the k8s namespace in the config clusters.
#
# Will grant 'clusterViewer' role, needed to list the config clusters (container.clusters,resourcemanager.projects)(.get,.list)
# TODO: document alternative (storing cluster config in mesh.env)
setup-gsa:
	gcloud --project ${PROJECT_ID} iam service-accounts create k8s-${WORKLOAD_NAMESPACE} \
      --display-name "Service account with access to ${WORKLOAD_NAMESPACE} k8s namespace" || true

	# Grant the GSA running the workload permission to connect to the config clusters in the config project.
	# Will use the 'SetQuotaProject' - otherwise the GKE API must be enabled in the workload project.
	gcloud --project ${CONFIG_PROJECT_ID} projects add-iam-policy-binding \
            ${CONFIG_PROJECT_ID} \
            --member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --role="roles/container.clusterViewer"
	# This allows the GSA to use the GKE and other APIs in the 'config cluster' project.
	gcloud --project ${CONFIG_PROJECT_ID} projects add-iam-policy-binding \
            ${CONFIG_PROJECT_ID} \
            --member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --role="roles/serviceusage.serviceUsageConsumer"

	# Also allow the use of TD
	gcloud projects add-iam-policy-binding ${PROJECT_ID} \
	  --member serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
	   --role roles/trafficdirector.client

# Setup workload identity - used to make the KSA and GSA 'equivlent'.
# This allows metadata server to impersonate the GSA.
setup-wi:
    # Map the KSA to the GSA (Workload identity)
	gcloud iam service-accounts add-iam-policy-binding \
		--role roles/iam.workloadIdentityUser \
		--member "serviceAccount:${CONFIG_PROJECT_ID}.svc.id.goog[${WORKLOAD_NAMESPACE}/default]" \
		k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com
	# K8S side of the mapping.
	kubectl annotate serviceaccount \
        --namespace ${WORKLOAD_NAMESPACE} default \
        iam.gke.io/gcp-service-account=k8s-${WORKLOAD_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
    # At this point, Pods running as default KSA can test:
	# curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/

setup-hgate: PROJECT_NUMBER=$(shell gcloud projects describe ${CONFIG_PROJECT_ID} --format="value(projectNumber)")
setup-hgate:
	gcloud run services add-iam-policy-binding ${SERVICE} \
      --member="serviceAccount:${CONFIG_PROJECT_ID}.svc.id.goog[istio-system/default]" \
      --role='roles/run.invoker'
	gcloud run services add-iam-policy-binding ${SERVICE} \
      --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-meshdataplane.iam.gserviceaccount.com" \
      --role='roles/run.invoker'

setup-rbac:
	kubectl --context ${K8S_CONTEXT} create ns ${WORKLOAD_NAMESPACE} || true
	cat ../../manifests/google-service-account-template.yaml | envsubst  | kubectl --context ${K8S_CONTEXT} apply -f -

# Setup service must be called after deploy
setup-service: setup-sni

# Setup the SNI routing for  SERVICE using hgate internal load balancer.
setup-sni: K_SERVICE=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)" | sed s,https://,, | sed s/.a.run.app// )
setup-sni: SNI_GATE_IP=$(shell kubectl -n istio-system get service internal-hgate -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
setup-sni:
	echo Setting up SNI route ${K_SERVICE} ${SNI_GATE_IP}
	cat ../../manifests/sni-service-template.yaml | SNI_GATE_IP=${SNI_GATE_IP} K_SERVICE=${K_SERVICE} envsubst  | kubectl apply -f -

cleanup:
	kubectl delete ns ${WORKLOAD_NAMESPACE} || true
	gcloud --project ${CONFIG_PROJECT_ID} projects remove-iam-policy-binding \
            ${CONFIG_PROJECT_ID} \
            --member="serviceAccount:k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --role="roles/container.clusterViewer" || true
	gcloud --project ${PROJECT_ID} iam service-accounts -q delete k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com || true
	gcloud alpha run -q services delete ${SERVICE}

logs-project:
	gcloud logging read 'resource.type = "project" OR resource.type = "cloud_run_revision"'

# textPayload:SyncAddress --limit=50 --format=json
logs:
	#gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.location = "us-central1" AND resource.labels.service_name="fortio${SUFFIX}"'
	gcloud --project ${PROJECT_ID} logging read \
		--format "csv(textPayload)" \
		--freshness 1h \
 		'resource.type="cloud_run_revision" AND resource.labels.location = "us-central1" AND resource.labels.service_name="${SERVICE}"'

# In order to use shared VPC, cloudrun must have the permission.
# Once per project.
vpc-access: PROJECT_NUMBER=$(shell gcloud projects describe ${PROJECT_ID} --format="value(projectNumber)")
vpc-access:
	# Requires compute.organizations.enableXpnHost
#	gcloud projects add-iam-policy-binding ${CONFIG_PROJECT_ID} \
#		--role roles/vpcaccess.serviceAgent \
#		--member "serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-vpcaccess.iam.gserviceaccount.com"
	gcloud compute shared-vpc enable ${CONFIG_PROJECT_ID}
	gcloud compute shared-vpc associated-projects add ${PROJECT_ID} \
    	--host-project ${CONFIG_PROJECT_ID}

	gcloud projects add-iam-policy-binding ${CONFIG_PROJECT_ID} \
		--role roles/vpcaccess.user \
		--member "serviceAccount:service-${PROJECT_NUMBER}@serverless-robot-prod.iam.gserviceaccount.com" \


setupcon-sharedvpc:
	gcloud services --project ${CONFIG_PROJECT_ID} enable vpcaccess.googleapis.com
	gcloud compute --project ${CONFIG_PROJECT_ID} networks vpc-access connectors create serverlesscon \
    --region ${REGION} \
    --range 10.8.0.0/28 \
    --min-instances 2 \
    --max-instances 10

