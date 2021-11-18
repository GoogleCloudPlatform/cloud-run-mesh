// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/k8s"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/sts"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	container "cloud.google.com/go/container/apiv1"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"

	"k8s.io/client-go/kubernetes"
	kubeconfig "k8s.io/client-go/tools/clientcmd/api"
	// Required for k8s client to link in the authenticator
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	containerpb "google.golang.org/genproto/googleapis/container/v1"
)

// Integration with GCP - use metadata server or GCP-specific env variables to auto-configure connection to a
// GKE cluster and extract metadata.

// Using the metadata package, which connects to 169.254.169.254, metadata.google.internal or $GCE_METADATA_HOST (http, no prefix)
// Will attempt to guess if running on GCP if env variable is not set.
// Note that requests are using a 2 sec timeout.

// TODO:  finish hub.

// Cluster wraps cluster information for a discovered hub or gke cluster.
type Cluster struct {
	ClusterName     string
	ClusterLocation string
	ProjectId       string

	GKECluster *containerpb.Cluster

	KubeConfig *kubeconfig.Config
}

var (
	GCPInitTime time.Duration
)

// configFromEnvAndMD will attempt to configure ProjectId, ClusterName, ClusterLocation, ProjectNumber, used on GCP
// Metadata server will be tried if env variables don't exist.
func configFromEnvAndMD(ctx context.Context, kr *mesh.KRun) {
	if kr.ProjectId == "" {
		kr.ProjectId = os.Getenv("PROJECT_ID")
	}

	if kr.ClusterName == "" {
		kr.ClusterName = os.Getenv("CLUSTER_NAME")
	}

	if kr.ClusterLocation == "" {
		kr.ClusterLocation = os.Getenv("CLUSTER_LOCATION")
	}

	if kr.ProjectNumber == "" {
		kr.ProjectNumber = os.Getenv("PROJECT_NUMBER")
	}

	// If ADC is set, we will only use the env variables. Else attempt to init from metadata server.
	if os.Getenv("APPLICATION_DEFAULT_CREDENTIALS") != "" {
		return
	}

	t0 := time.Now()
	if metadata.OnGCE() {
		// TODO: detect if the cluster is k8s from some env ?
		// If ADC is set, we will only use the env variables. Else attempt to init from metadata server.
		metaProjectId, _ := metadata.ProjectID()
		if kr.ProjectId == "" {
			kr.ProjectId = metaProjectId
		}

		//instanceID, _ := metadata.InstanceID()
		//instanceName, _ := metadata.InstanceName()
		//zone, _ := metadata.Zone()
		//pAttr, _ := metadata.ProjectAttributes()
		//hn, _ := metadata.Hostname()
		//iAttr, _ := metadata.InstanceAttributes()

		email, _ := metadata.Email("default")
		// In CloudRun: Additional metadata: iid 00bf4b...f23 iname  iattr [] zone us-central1-1 hostname  pAttr [] email k8s-fortio@wlhe-cr.iam.gserviceaccount.com

		//log.Println("Additional metadata:", "iid", instanceID, "iname", instanceName, "iattr", iAttr,
		//	"zone", zone, "hostname", hn, "pAttr", pAttr, "email", email)

		if kr.Namespace == "" {
			if strings.HasPrefix(email, "k8s-") {
				parts := strings.Split(email[4:], "@")
				kr.Namespace = parts[0]
				if mesh.Debug {
					log.Println("Defaulting Namespace based on email: ", kr.Namespace, email)
				}
			}
		}
		var err error
		if kr.InCluster && kr.ClusterName == "" {
			kr.ClusterName, err = metadata.Get("instance/attributes/cluster-name")
			if err != nil {
				log.Println("Can't find cluster name")
			}
		}
		if kr.InCluster && kr.ClusterLocation == "" {
			kr.ClusterLocation, err = metadata.Get("instance/attributes/cluster-location")
			if err != nil {
				log.Println("Can't find cluster location")
			}
		}

		if kr.InstanceID == "" {
			kr.InstanceID, _ = metadata.InstanceID()
		}
		if mesh.Debug {
			log.Println("Configs from metadata ", time.Since(t0))
		}
		log.Println("Running as GSA ", email, kr.ProjectId, kr.ProjectNumber, kr.InstanceID, kr.ClusterLocation)
	}
}

func RegionFromMetadata() (string, error) {
	v, err := metadata.Get("instance/region")
	if err != nil {
		return "", err
	}
	vs := strings.SplitAfter(v, "/regions/")
	if len(vs) != 2 {
		return "", fmt.Errorf("malformed region value split into %#v", vs)
	}
	return vs[1], nil
}

func InitGCP(ctx context.Context, kr *mesh.KRun) error {
	// Avoid direct dependency on GCP libraries - may be replaced by a REST client or different XDS server discovery.
	kc := &k8s.K8S{Mesh: kr}
	err := kc.K8SClient(ctx)
	if err != nil {
		return err
	}
	// Load GCP env variables - will be needed.
	configFromEnvAndMD(ctx, kc.Mesh)

	// Init additional GCP-specific env, and load the k8s cluster using discovery
	initGKE(ctx, kc)
	if kc.Client == nil {
		return errors.New("No cluster found")
	}

	kr.Cfg = kc
	kr.TokenProvider = kc
	kr.Client = kc.Client

	// After the config was loaded.
	kr.PostConfigLoad = PostConfigLoad
	return err
}

func PostConfigLoad(ctx context.Context, kr *mesh.KRun) error {
	var err error
	// TODO: Use MeshCA if citadel is not in cluster
	tokenProvider, err := sts.NewSTS(kr)

	// This doesn't work
	//  Could not use the REFLECTED_SPIFFE subject mode because the caller does not have a SPIFFE identity. Please visit the CA Service documentation to ensure that this is a supported use-case
	//  tokenProvider.MDPSA = true
	// The token MUST be the federated access token

	tokenProvider.UseAccessToken = true // even if audience is provided.

	var ol []grpc.DialOption
	ol = append(ol, grpc.WithPerRPCCredentials(tokenProvider))
	//ol = append(ol, OTELGRPCClient()...)

	// TODO: only if mesh_env contains a WorkloadCertificateConfig with endpoint starting with //privateca.googleapis.com
	// Errors results to fallback to pilot-agent and istio.
	cas := kr.Config("CAS", "")
	if cas != "" {
		kr.CSRSigner, err = NewCASCertProvider("projects/"+kr.ProjectId+
				"/locations/"+kr.Region()+"/caPools/mesh", ol)
	}
	return err
}


// InitGCP loads GCP-specific metadata and discovers the config cluster.
// This step is skipped if user has explicit configuration for required settings.
//
// Namespace,
// ProjectId, ProjectNumber
// ClusterName, ClusterLocation
func initGKE(ctx context.Context, kc *k8s.K8S) error {
	if kc.Client != nil {
		// Running in-cluster or using kube config
		return nil
	}

	t0 := time.Now()
	var kConfig *kubeconfig.Config
	var err error

	// TODO: attempt to get the config project ID from a label on the workload or project
	// (if metadata servere or CR can provide them)

	kr := kc.Mesh
	configProjectID := kr.ProjectId
	configLocation := kr.ClusterLocation
	configClusterName := kr.ClusterName

	if kr.MeshAddr != nil {
		if kr.MeshAddr.Scheme == "gke" {
			configProjectID = kr.MeshAddr.Host
		} else if kr.MeshAddr.Host == "container.googleapis.com" {
			// Not using the hub resourceLink format:
			//    container.googleapis.com/projects/wlhe-cr/locations/us-central1-c/clusters/asm-cr
			// or the 'selfLink' from GKE list API
			// "https://container.googleapis.com/v1/projects/wlhe-cr/locations/us-west1/clusters/istio"

			configProjectID = kr.MeshAddr.Host
			if len(kr.MeshAddr.Path) > 1 {
				parts := strings.Split(kr.MeshAddr.Path, "/")
				for i := 0 ; i < len(parts); i++ {
					if parts[i] == "projects" && i+1 < len(parts) {
						configProjectID = parts[i+1]
					}
					if parts[i] == "locations" && i+1 < len(parts) {
						configLocation = parts[i+1]
					}
					if parts[i] == "clusters" && i+1 < len(parts) {
						configClusterName = parts[i+1]
					}
				}
			}
		}
	}

	if configProjectID == "" {
		// GCP can't be initialized without a project ID
		return nil
	}

	var cl *Cluster
	if configLocation == "" || configClusterName == "" {
		// ~500ms
		label := "mesh_id"
		// Try to get the region from metadata server. For Cloudrun, this is not the same with the cluster - it may be zonal
		myRegion, _ := RegionFromMetadata()
		if myRegion == "" {
			myRegion = configLocation
		}
		if kr.MeshAddr != nil && kr.MeshAddr.Scheme == "gke" {
			// Explicit mesh config clusters, no label selector ( used for ASM clusters in current project )
			label = ""
		}
		log.Println("Selecting a GKE cluster ", kr.ProjectId, configProjectID, myRegion)
		cll, err := AllClusters(ctx, kr, configProjectID, label, "")
		if err != nil {
			return err
		}

		if len(cll) == 0 {
			return nil // no cluster to use
		}


		cl = findCluster(kc, cll, myRegion, cl)
		// TODO: connect to cluster, find istiod - and keep trying until a working one is found ( fallback )
	} else {
		// Explicit override - user specified the full path to the cluster.
		// ~400 ms
		if mesh.Debug {
			log.Println("Load GKE cluster explicitly", configProjectID, configLocation, configClusterName)
		}
		cl, err = GKECluster(ctx, kr, configProjectID, configLocation, configClusterName)
		if err != nil {
			return err
		}
		if err != nil {
			log.Println("Failed in NewForConfig", kr, err)
			return err
		}
	}

	kr.ProjectId = configProjectID

	kr.TrustDomain = configProjectID + ".svc.id.goog"
	kConfig = cl.KubeConfig
	if kr.ClusterName == "" {
		kr.ClusterName = cl.ClusterName
	}
	if kr.ClusterLocation == "" {
		kr.ClusterLocation = cl.ClusterLocation
	}

	GCPInitTime = time.Since(t0)

	rc, err := restConfig(kConfig)
	if err != nil {
		return err
	}
	kc.Client, err = kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}

	return nil
}

func restConfig(kc *kubeconfig.Config) (*rest.Config, error) {
	// TODO: set default if not set ?
	return clientcmd.NewNonInteractiveClientConfig(*kc, "", &clientcmd.ConfigOverrides{}, nil).ClientConfig()
}

func findCluster(kr *k8s.K8S, cll []*Cluster, myRegion string, cl *Cluster) *Cluster {
	if kr.Mesh.ClusterName != "" {
		for _, c := range cll {
			if myRegion != "" && !strings.HasPrefix(c.ClusterLocation, myRegion) {
				continue
			}
			if c.ClusterName == kr.Mesh.ClusterName {
				cl = c
				break
			}
		}
		if cl == nil {
			for _, c := range cll {
				if c.ClusterName == kr.Mesh.ClusterName {
					cl = c
					break
				}
			}
		}
	}

	// First attempt to find a cluster in same region, with the name prefix istio (TODO: label or other way to identify
	// preferred config clusters)
	if cl == nil {
		for _, c := range cll {
			if myRegion != "" && !strings.HasPrefix(c.ClusterLocation, myRegion) {
				continue
			}
			if strings.HasPrefix(c.ClusterName, "istio") {
				cl = c
				break
			}
		}
	}
	if cl == nil {
		for _, c := range cll {
			if myRegion != "" && !strings.HasPrefix(c.ClusterLocation, myRegion) {
				continue
			}
			cl = c
			break
		}
	}
	if cl == nil {
		for _, c := range cll {
			if strings.HasPrefix(c.ClusterName, "istio") {
				cl = c
			}
		}
	}
	// Nothing in same region, pick the first
	if cl == nil {
		cl = cll[0]
	}
	return cl
}

func GKECluster(ctx context.Context, kr *mesh.KRun, p, l, clusterName string) (*Cluster, error) {
	opts := []option.ClientOption{}
	if p != kr.ProjectId {
		opts = append(opts, option.WithQuotaProject(p))
	}
	cl, err := container.NewClusterManagerClient(ctx, opts...)
	if err != nil {
		log.Println("Failed NewClusterManagerClient", p, l, clusterName, err)
		return nil, err
	}

	for i := 0; i < 5; i++ {
		gcr := &containerpb.GetClusterRequest{
			Name: fmt.Sprintf("projects/%s/locations/%s/cluster/%s", p, l, clusterName),
		}
		c, e := cl.GetCluster(ctx, gcr)
		if e == nil {
			rc := &Cluster{
				ProjectId:       p,
				ClusterLocation: c.Location,
				ClusterName:     c.Name,
				GKECluster:      c,
				KubeConfig:      addClusterConfig(c, p, l, clusterName),
			}

			return rc, nil
		}
		log.Println("Failed GetCluster, retry", gcr, p, l, clusterName, err)
		time.Sleep(1 * time.Second)
		err = e
	}
	return nil, err
}

func ProjectNumber(p string) string {
	ctx := context.Background()

	cr, err := crm.NewService(ctx)
	if err != nil {
		return ""
	}
	pdata, err := cr.Projects.Get(p).Do()
	if err != nil {
		log.Println("Error getting project number", p, err)
		return ""
	}

	// This is in v1 - v3 has it encoded in name.
	return strconv.Itoa(int(pdata.ProjectNumber))
}

func AllClusters(ctx context.Context, kr *mesh.KRun, configProjectId string,
	label string, meshID string) ([]*Cluster, error) {
	clustersL := []*Cluster{}

	if configProjectId == "" {
		configProjectId = kr.ProjectId
	}

	opts := []option.ClientOption{}
	if configProjectId != kr.ProjectId {
		opts = append(opts, option.WithQuotaProject(configProjectId))
	}
	cl, err := container.NewClusterManagerClient(ctx,opts...)
	if err != nil {
		return nil, err
	}

	if configProjectId == "" {
		configProjectId = kr.ProjectId
	}
	clcr := &containerpb.ListClustersRequest{
		Parent: "projects/" + configProjectId + "/locations/-",
	}
	clusters, err := cl.ListClusters(ctx, clcr)
	if err != nil {
		return nil, err
	}

	for _, c := range clusters.Clusters {
		if label != "" { // Filtered by label - if the filter is specified, ignore non-labeled clusters
			if meshID == "" { // If a value for label was specified, used it for filtering
				if c.ResourceLabels[label] == "" {
					continue
				}
			} else {
				if c.ResourceLabels[label] != meshID {
					continue
				}
			}
		}
		clustersL = append(clustersL, &Cluster{
			ProjectId:       configProjectId,
			ClusterName:     c.Name,
			ClusterLocation: c.Location,
			GKECluster:      c,
			KubeConfig:      addClusterConfig(c, configProjectId, c.Location, c.Name),
		})
	}
	return clustersL, nil
}

func addClusterConfig(c *containerpb.Cluster, p, l, clusterName string) *kubeconfig.Config {
	kc := kubeconfig.NewConfig()
	caCert, err := base64.StdEncoding.DecodeString(c.MasterAuth.ClusterCaCertificate)
	if err != nil {
		caCert = nil
	}

	ctxName := "gke_" + p + "_" + l + "_" + clusterName

	// We need a KUBECONFIG - tools/clientcmd/api/Config object
	kc.CurrentContext = ctxName
	kc.Contexts[ctxName] = &kubeconfig.Context{
		Cluster:  ctxName,
		AuthInfo: ctxName,
	}
	kc.Clusters[ctxName] = &kubeconfig.Cluster{
		Server:                   "https://" + c.Endpoint,
		CertificateAuthorityData: caCert,
	}
	kc.AuthInfos[ctxName] = &kubeconfig.AuthInfo{
		AuthProvider: &kubeconfig.AuthProviderConfig{
			Name: "gcp",
		},
	}
	kc.CurrentContext = ctxName

	return kc
}
