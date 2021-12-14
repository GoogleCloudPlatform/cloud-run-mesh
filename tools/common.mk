
# Common makefile targets for automating build and deployment.
#
# Args:
# SERVICE - the name of the cloudrun service
# IMAGE - docker image

deploy: cloudrun setup-sni

cloudrun:
	gcloud alpha run deploy ${SERVICE} -q \
        		  --execution-environment=gen2 \
        		  --platform managed --project ${PROJECT_ID} --region ${REGION} \
        		  --service-account=${CLOUDRUN_SERVICE_ACCOUNT} \
                  --vpc-connector projects/${CONFIG_PROJECT_ID}/locations/${REGION}/connectors/serverlesscon \
                 \
                 ${RUN_EXTRA} \
                 --no-allow-unauthenticated \
                 --use-http2 \
                 --set-env-vars MESH_TENANT=- \
                 --set-env-vars=MESH=gke://${CONFIG_PROJECT_ID} \
        		 --set-env-vars="DEPLOY=$(shell date +%y%m%d-%H%M)" \
                 --port 15009  \
                 \
                 --image ${REPO}/testapp:${TAG}-distroless

setup-sni: K_SERVICE=$(shell gcloud run services --project ${PROJECT_ID} --region ${REGION} describe ${SERVICE} --format="value(status.address.url)" | sed s,https://,, | sed s/.a.run.app// )
setup-sni: SNI_GATE_IP=$(shell kubectl -n istio-system get service internal-hgate -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
setup-sni:
	echo Setting up SNI route ${K_SERVICE} ${SNI_GATE_IP}
	cat manifests/sni-service-template.yaml | WORKLOAD_NAME=${SERVICE} SNI_GATE_IP=${SNI_GATE_IP} \
		WORKLOAD_NAMESPACE=${WORKLOAD_NAMESPACE} \
		K_SERVICE=${K_SERVICE} envsubst  | kubectl apply -f -


logs:
	gcloud --project ${PROJECT_ID} logging read \
		--format "csv(textPayload,httpRequest,trace)" \
		--freshness 1h \
		'resource.type="cloud_run_revision" AND resource.labels.location = "us-central1" AND resource.labels.service_name="${SERVICE}"'

################ Testing / local dev #################
# For testing/dev in local docker
PORT_PREFIX ?= 1600

# Run a mesh-enabled docker image.
# Params: IMAGE
docker/run: ADC?=${HOME}/.config/gcloud/legacy_credentials/$(shell gcloud config get-value core/account)/adc.json
docker/run:
	docker run -it --name app --rm \
		--cap-add=NET_ADMIN \
 	    -p 127.0.0.1:${PORT_PREFIX}0:15000 \
    	-p 127.0.0.1:${PORT_PREFIX}9:15009 \
 		-e PROJECT_ID=${PROJECT_ID} \
		-e GOOGLE_APPLICATION_CREDENTIALS=/var/run/secrets/google/google.json \
		-v ${ADC}:/var/run/secrets/google/google.json:ro \
		${_RUN_EXTRA} \
		${IMAGE} \
	   ${_RUN_CMD}

docker/sh: ADC?=${HOME}/.config/gcloud/legacy_credentials/$(shell gcloud config get-value core/account)/adc.json
docker/sh:
	docker run -it --name app --rm \
		--cap-add=NET_ADMIN \
 	    -p 127.0.0.1:${PORT_PREFIX}0:15000 \
    	-p 127.0.0.1:${PORT_PREFIX}9:15009 \
 		-e PROJECT_ID=${PROJECT_ID} \
		-e GOOGLE_APPLICATION_CREDENTIALS=/var/run/secrets/google/google.json \
		-v ${ADC}:/var/run/secrets/google/google.json:ro \
		--entrypoint /busybox/sh \
		${_RUN_EXTRA} \
		${IMAGE} \
	   ${_RUN_CMD}
