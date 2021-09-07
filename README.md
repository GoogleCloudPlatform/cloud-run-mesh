# Running a CloudRun or docker image in a mesh environment

This repository implements a small launcher that prepares a mesh environment and starts the user application.

In K8S, the mesh implementation relies on a mutating webhook that patches the Pod, injecting for required environment. 
Docker and CloudRun images do not have an injector - this application is playing the same role, using the K8S and
GCP APIs to setup iptables and the sidecar process or the proxyless bootstrap.

This supports running an app:
- in an Istio-like environment with a Sidecar and iptables interception
- if iptables is not available (gVisor, regular docker, dev machine), configure 'whitebox' mode ( HTTP_PROXY and localhost port 
  forwarding for TCP)
- in proxyless gRPC mode for applications that natively support XDS and mesh, without iptables or sidecar.

The launcher is responsible for:
- discovering a GKE/K8S cluster based on environment (metadata server, env variables), and getting credentials and config
- discovering the XDS address and config (root certificates, metadata)
- setting up iptables ( equivalent to the init container in K8S ), using pilot-agent
- launching pilot-agent and envoy
- configuring pilot-agent to intercept DNS
- launching the application - after the setup is ready
- creating any necessary tunnels to allow use of mTLS, based on the HBONE (tunneling over HTTP/2) proposal in Istio.

The repository also includes a specialised SNI-routing gateway that allows any mesh node using mTLS to route back 
to CloudRun with the proper authentication and tunneling for mTLS.

The user application should be able to communicate with other mesh workloads - in Pods, VMs or other CloudRun 
services using mTLS and the mesh launcher.

The code is based on the Istio VM startup script and injection template and will need to be kept in sync with future
changes in the mesh startup.

# Setup instructions

Common environment variables used in this document:

```shell

export PROJECT_ID=wlhe-cr
export CLUSTER_LOCATION=us-central1-c
export CLUSTER_NAME=asm-cr
# CloudRun region 
export REGION=us-central1

export WORKLOAD_NAMESPACE=fortio # Namespace where the CloudRun service will 'attach'
export WORKLOAD_NAME=cloudrun

# Name of the service account running the CloudRun service. It is recommended to use a dedicated SA for each K8S namespace
# and keep permissions as small as possible. 
# By default the namespace is extracted from the GSA name - if using a different SA or naming, WORKLOAD_NAMESPACE env
# is required when deploying the docker image. 
# (This may change as we polish the UX)
export WORKLOAD_SERVICE_ACCOUNT=k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com

# Name for the cloudrun service - will use the same as the workload.
# Note that the service must be unique for region, if you want the same name in multiple namespace you must 
# use explicit config for WORKLOAD_NAME when deploying and unique cloudrun service name
export CLOUDRUN_SERVICE=${WORKLOAD_NAME}


````


## Installation 

Requirements:
- For each region, you need a Serverless connector, using the same network as the GKE cluster(s) and VMs. CloudRun will
   use it to communicate with the Pods/VMs.
- 'gen2' VM required for iptables. 'gen1' works in 'whitebox mode', using HTTP_PROXY. 
- The project should be allowed by policy to use 'allow-unauthenticated'. WIP to eliminate this limitation.

You need to have gcloud and kubectl, and admin permissions for the project and cluster. 

After installation, new services can be configured for namespaces using only namespace-level permissions in K8S.


### Cluster setup (once per cluster)

1. If you don't already have a cluster with managed ASM, follow [Install docs](https://cloud.google.com/service-mesh/docs/scripted-install/gke-install) 

2. Configure the in-cluster gateway and permissions. (this step is temporary, WIP to remove it and have the controller created automatically)

```shell 

kubectl apply -k github.com/costinm/cloud-run-mesh/manifests/

```

### Serverless connector setup (once per project / region / VPC network)

For each region where GKE and CloudRun will be used, [install CloudRun connector](https://cloud.google.com/vpc/docs/configure-serverless-vpc-access)
Using the UI is usually easier - it does require a /28 range to be specified.
You can call the connector 'serverlesscon' - the name will be used when deploying the CloudRun service. 

If you already have a connector, you can continue to use it, and adjust the '--vpc-connector' parameter on the 
deploy command.

The connector MUST be on the same network with the GKE cluster.


### Google Service Account and Namespace Setup

The Google Service Account running the CloudRun service will be mapped to a K8S namespace. 

The service account used by CloudRun must be granted access to the GKE APIserver with minimal permissions, and must 
be allowed to get K8S tokens.

This steps can be run by a user or service account with namespace permissions in K8S - does not require k8s 
cluster admin. It does require IAM permissions on the project running the CloudRun service.


1. Create a google service account for the CloudRun app (recommended - one per namespace, to reduce permission  scope).

2. Grant '--role="roles/container.clusterViewer"' to the service account.

3. Grant RBAC permissions to the google service account, allowing it to access in-namespace config map and use 
   TokenReview for the default KSA. (this step is also temporary, WIP to make it optional). This is used to get the MeshCA 
   certificate and communicate with the managed control plane - Istio injector is mounting the equivalent tokens. 

```shell


gcloud --project ${PROJECT_ID} iam service-accounts create k8s-${WORKLOAD_NAMESPACE} \
      --display-name "Service account with access to ${WORKLOAD_NAMESPACE} k8s namespace"

# Allow the GSA to access GKE clusters, as viewer
gcloud --project ${PROJECT_ID} projects add-iam-policy-binding \
            ${PROJECT_ID} \
            --member="serviceAccount:${WORKLOAD_SERVICE_ACCOUNT}" \
            --role="roles/container.clusterViewer"

# Make sure we use the current config cluster
gcloud container clusters get-credentials ${CLUSTER_NAME} --zone ${CLUSTER_LOCATION} --project ${PROJECT_ID}

# Make sure the namespace is created
kubectl create ns ${WORKLOAD_NAMESPACE} 

# Uses WORKLOAD_NAMESPACE and PROJECT_ID to associate the Google Service Account with the K8S Namespace.
cat manifests/google-service-account-template.yaml | envsubst | kubectl apply -f -

```

### Build a docker image containing the app and the sidecar

samples/fortio/Dockerfile contains an example Dockerfile - you can also use the pre-build image
`grc.io/wlhe-cr/fortio-cr:main`

You can build the app with the normal docker command:

```shell

# Get the base image. You can also create a 'golden' base, starting with ASM proxy image and adding the 
# startup helper (krun) and other files or configs you need. 
# The application will be added to the base.
export GOLDEN_IMAGE=gcr.io/wlhe-cr/krun:main

# Target image 
export IMAGE=gcr.io/${PROJECT_ID}/fortio-cr:main

(cd samples/fortio && docker build . -t ${IMAGE} --build-arg=BASE=${GOLDEN_IMAGE} )

docker push ${IMAGE}

```


### Deploy the image to CloudRun

Deploy the service, with explicit configuration:


```shell

gcloud alpha run deploy ${CLOUDRUN_SERVICE} \
          --platform managed \
          --project ${PROJECT_ID} \
          --region ${REGION} \
          --execution-environment=gen2 \
          --service-account=k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com \
          --allow-unauthenticated \
          --use-http2 \
          --port 15009 \
          --image ${IMAGE} \
          --vpc-connector projects/${PROJECT_ID}/locations/${REGION}/connectors/serverlesscon \
         --set-env-vars="CLUSTER_NAME=${CLUSTER_NAME}" \
         --set-env-vars="CLUSTER_LOCATION=${CLUSTER_LOCATION}" 
         
```

For versions of 'gcloud' older than 353.0, replace `--execution-environment=gen2` with `--sandbox=minivm`

CLUSTER_NAME and CLUSTER_LOCATION will be optional - krun will pick a config cluster in the same region  that is setup
with MCP, and fallback to other config cluster if the local cluster is unavailable. Cluster names starting with 'istio' 
will be used first in a region. (Will likely change to use a dedicated label on the project - WIP)

- `gcloud run deploy SERVICE --platform=managed --project --region` is common required parameters
- `--execution-environment=gen2` is currently required to have iptables enabled. Without it the 'whitebox' mode will
   be used (still WIP)
-  `--service-account` is recommended for 'minimal priviledge'. The service account will act as a K8S SA, and have its
   RBAC permissions
-   `--allow-unauthenticated` is only needed temporarily if you want to ssh into the instance for debug. WIP to fix this.
-  `--use-http2`  and `--port 15009` are required 

### Testing

1. Deploy an in-cluster application. The CloudRun service will connect to it:

```shell
gcloud container clusters get-credentials ${CLUSTER_NAME} --zone ${CLUSTER_LOCATION} --project ${PROJECT_ID}

kubectl label namespace fortio istio-injection- istio.io/rev=asm-managed --overwrite
kubectl apply -f https://raw.githubusercontent.com/costinm/cloud-run-mesh/main/samples/fortio/in-cluster.yaml

```


2. Use the CloudRun service to connect to the in-cluster workload. Use the CR service URL with /fortio/ path to
access the UI of the app.

In the UI, use "http://fortio.fortio.svc:8080" and you should see the results for testing the connection to the 
in-cluster app.

In general, the CloudRun applications can use any K8S service name - including shorter version for same-namespace
services. So fortio, fortio.fortio, fortio.fortio.svc.cluster.local also work.

In this example the in-cluster application is using ASM - it is also possible to access regular K8S applications
without a sidecar. 

## Configuration options 

When running in CloudRun, default automatic configuration is based on environment variables, metadata server and calls 
to GKE APIs. For debugging (as a regular process), when running with a regular docker or to override the defaults, the 
settings must be explicit.

- WORKLOAD_NAMESPACE - default value extracted from the service account running the CloudRun service
- WORKLOAD_NAME - default value is the CloudRun service name. Also used as 'canonical service'.
- PROJECT_ID - default is same project as the CloudRun service.
- CLUSTER_LOCATION - default is same region as the CloudRun service. If CLUSTER_NAME is not specified, a cluster with
  ASM in the region or zone will be picked.
- CLUSTER_NAME - if not set, clusters in same region or a zone in the region will be picked. Cluster names starting with
  'istio' are currently picked first. (WIP to define a labeling or other API for cluster selection)

Also for local development:
- GOOGLE_APPLICATION_CREDENTIALS must be set to a file that is mounted, containing GSA credentials. 
- Alternatively, a KUBECONFIG file must be set and configured for the intended cluster.


# Debugging

Since CloudRun and docker doesn't support kubectl exec or port-forward, we include a minimal sshd server that is 
enabled using a K8S Secret or environment variables. See samples/ssh for setup example. 

You can ssh into the service and forward ports using a regular ssh client and a ProxyCommand that implements 
the tunneling over HTTP/2:

```shell

# Compile the proxy command
go install ./cmd/hbone

# Set with your own service URL
export SERVICE_URL=https://fortio-asm-cr-icq63pqnqq-uc.a.run.app:443

ssh -F /dev/null -o StrictHostKeyChecking=no -o "UserKnownHostsFile /dev/null" \
    -o ProxyCommand='hbone ${SERVICE_URL}/_hbone/22' root@proxy
```
