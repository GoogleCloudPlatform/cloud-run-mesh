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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"

	container "cloud.google.com/go/container/apiv1"

	"github.com/costinm/cloud-run-mesh/pkg/mesh"

	"k8s.io/client-go/kubernetes"
	kubeconfig "k8s.io/client-go/tools/clientcmd/api"
	// Required for k8s client to link in the authenticator
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	gkehub "cloud.google.com/go/gkehub/apiv1beta1"
	crm "google.golang.org/api/cloudresourcemanager/v1"

	gkehubpb "google.golang.org/genproto/googleapis/cloud/gkehub/v1beta1"
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
	HubCluster *gkehubpb.Membership

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

	if os.Getenv("APPLICATION_DEFAULT_CREDENTIALS") != "" {
		// Not using metadata server, except for project number if not set
		if kr.ProjectNumber == "" && kr.ProjectId != "" {
			kr.ProjectNumber = ProjectNumber(kr.ProjectId)
			log.Println("Got project number from GCP API", kr.ProjectNumber)
		}
		return
	}

	t0 := time.Now()
	if metadata.OnGCE() {
		// TODO: detect if the cluster is k8s from some env ?
		// If ADC is set, we will only use the env variables. Else attempt to init from metadata server.
		log.Println("Detecting GCE ", time.Since(t0))
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

		//if kr.ClusterLocation == "" {
		//	kr.ClusterLocation, _ = RegionFromMetadata()
		//}
		//
		if kr.ProjectNumber == "" && kr.ProjectId == metaProjectId {
			// If project Id explicitly set, and not same as what metadata reports - fallback to getting it from GCP
			kr.ProjectNumber, _ = metadata.NumericProjectID()
		}
		if kr.ProjectNumber == "" {
			kr.ProjectNumber = ProjectNumber(kr.ProjectId)
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

func TokenGKE(ctx context.Context, aud string) (string, error) {
	uri := fmt.Sprintf("instance/service-accounts/default/identity?audience=%s", aud)
	tok, err := metadata.Get(uri)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func Token(ctx context.Context, aud string) (string, error) {
	uri := fmt.Sprintf("instance/service-accounts/default/identity?audience=%s&format=full", aud)
	tok, err := metadata.Get(uri)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// detectAuthEnv will use the JWT token that is mounted in istiod to set the default audience
// and trust domain for Istiod, if not explicitly defined.
// K8S will use the same kind of tokens for the pods, and the value in istiod's own token is
// simplest and safest way to have things match.
//
// Note that K8S is not required to use JWT tokens - we will fallback to the defaults
// or require explicit user option for K8S clusters using opaque tokens.
//
// Use with:
//		t,err := Token(ctx, kr.ProjectId + ".svc.id.goog")
//		if err != nil {
//			log.Println("Failed to get id token ", err)
//		} else {
//			detectAuthEnv(t)
//		}
//
// Copied from Istio
func detectAuthEnv(jwt string) (*JwtPayload, error) {
	jwtSplit := strings.Split(jwt, ".")
	if len(jwtSplit) != 3 {
		return nil, fmt.Errorf("invalid JWT parts: %s", jwt)
	}
	//azp,"email","exp":1629832319,"iss":"https://accounts.google.com","sub":"1118295...
	payload := jwtSplit[1]

	payloadBytes, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt: %v", err.Error())
	}

	structuredPayload := &JwtPayload{}
	err = json.Unmarshal(payloadBytes, &structuredPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt: %v", err.Error())
	}

	return structuredPayload, nil
}

type JwtPayload struct {
	// Aud is the expected audience, defaults to istio-ca - but is based on istiod.yaml configuration.
	// If set to a different value - use the value defined by istiod.yaml. Env variable can
	// still override
	Aud []string `json:"aud"`

	// Exp is not currently used - we don't use the token for authn, just to determine k8s settings
	Exp int `json:"exp"`

	// Issuer - configured by K8S admin for projected tokens. Will be used to verify all tokens.
	Iss string `json:"iss"`

	Sub string `json:"sub"`
}

func InitGCP(ctx context.Context, kr *mesh.KRun) error {
	// Load GCP env variables - will be needed.
	configFromEnvAndMD(ctx, kr)

	if kr.Client != nil {
		// Running in-cluster or using kube config
		return nil
	}

	t0 := time.Now()
	var kc *kubeconfig.Config
	var err error

	if kr.ProjectId == "" {
		// GCP can't be initialized without a project ID
		return nil
	}

	var cl *Cluster
	if kr.ClusterName == "" || kr.ClusterLocation == "" {
		// ~500ms
		cll, err := AllClusters(ctx, kr, "", "mesh_id", "")
		if err != nil {
			return err
		}

		if len(cll) == 0 {
			return nil // no cluster to use
		}

		// Try to get the region from metadata server. For Cloudrun, this is not the same with the cluster - it may be zonal
		myRegion, _ := RegionFromMetadata()
		if myRegion == "" {
			myRegion = kr.ClusterLocation
		}

		cl = findCluster(kr, cll, myRegion, cl)
		// TODO: connect to cluster, find istiod - and keep trying until a working one is found ( fallback )
	} else {
		// ~400 ms
		cl, err = GKECluster(ctx, kr.ProjectId, kr.ClusterLocation, kr.ClusterName)
		//rc, err := CreateRestConfig(kr, kc, kr.ProjectId, kr.ClusterLocation, kr.ClusterName)
		if err != nil {
			return err
		}
		//kr.Client, err = kubernetes.NewForConfig(rc)
		if err != nil {
			log.Println("Failed in NewForConfig", kr, err)
			return err
		}
	}

	kc = cl.KubeConfig
	if kr.ClusterName == "" {
		kr.ClusterName = cl.ClusterName
	}
	if kr.ClusterLocation == "" {
		kr.ClusterLocation = cl.ClusterLocation
	}
	GCPInitTime = time.Since(t0)

	rc, err := restConfig(kc)
	if err != nil {
		return err
	}
	kr.Client, err = kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}

	SaveKubeConfig(kc, "./var/run/.kube", "config")

	return nil
}

func findCluster(kr *mesh.KRun, cll []*Cluster, myRegion string, cl *Cluster) *Cluster {
	if kr.ClusterName != "" {
		for _, c := range cll {
			if myRegion != "" && !strings.HasPrefix(c.ClusterLocation, myRegion) {
				continue
			}
			if c.ClusterName == kr.ClusterName {
				cl = c
				break
			}
		}
		if cl == nil {
			for _, c := range cll {
				if c.ClusterName == kr.ClusterName {
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

func GKECluster(ctx context.Context, p, l, clusterName string) (*Cluster, error) {
	cl, err := container.NewClusterManagerClient(ctx)
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

// AllHub connects to GKE Hub and gets all clusters registered in the hub.
// TODO: document/validate GKE Connect auth mode
//
func AllHub(ctx context.Context, kr *mesh.KRun) ([]*Cluster, error) {
	cl, err := gkehub.NewGkeHubMembershipClient(ctx)
	if err != nil {
		return nil, err
	}

	mi := cl.ListMemberships(ctx, &gkehubpb.ListMembershipsRequest{
		Parent: "projects/" + kr.ProjectId + "/locations/-",
	})

	// Also includes:
	// - labels
	// - Endpoint - including GkeCluster resource link ( the GKE name)
	// - State - should be READY
	//
	ml := []*Cluster{}
	for {
		r, err := mi.Next()
		//fmt.Println(r, err)
		if err != nil || r == nil {
			log.Println("Listing hub", kr.ProjectId, err)
			break
		}
		mna := strings.Split(r.Name, "/")
		mn := mna[len(mna)-1]
		ctxName := "connectgateway_" + kr.ProjectId + "_" + mn
		kc := kubeconfig.NewConfig()
		kc.Contexts[ctxName] = &kubeconfig.Context{
			Cluster:  ctxName,
			AuthInfo: ctxName,
		}
		kc.Clusters[ctxName] = &kubeconfig.Cluster{
			Server: fmt.Sprintf("https://connectgateway.googleapis.com/v1beta1/projects/%s/memberships/%s",
				kr.ProjectNumber, mn),
		}
		kc.AuthInfos[ctxName] = &kubeconfig.AuthInfo{
			AuthProvider: &kubeconfig.AuthProviderConfig{
				Name: "gcp",
			},
		}

		// TODO: better way to select default
		kc.CurrentContext = ctxName

		c := &Cluster{
			ProjectId:   kr.ProjectId,
			ClusterName: r.Name,
			KubeConfig:  kc,
			HubCluster:  r,
		}
		// ExternalId is an UUID.

		// TODO: if GKE cluster, try to determine real cluster name, location, project
		ep := r.GetEndpoint()
		if ep != nil && ep.GkeCluster != nil {
			// Format: //container.googleapis.com/projects/PID/locations/LOC/clusters/NAME
			parts := strings.Split(ep.GkeCluster.ResourceLink, "/")
			if len(parts) == 9 && parts[2] == "container.googleapis.com" {
				c.ProjectId = parts[4]
				c.ClusterLocation = parts[6]
				c.ClusterName = parts[8]
			}
			log.Println("HUB:", parts)
		}

		ml = append(ml, c)

	}
	return ml, nil
}

func AllClusters(ctx context.Context, kr *mesh.KRun, defCluster string, label string, meshID string) ([]*Cluster, error) {
	clustersL := []*Cluster{}

	if kr.ProjectId == "" {
		configFromEnvAndMD(nil, kr)
	}
	if kr.ProjectId == "" {
		return nil, errors.New("requires PROJECT_ID")
	}

	cl, err := container.NewClusterManagerClient(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := cl.ListClusters(ctx, &containerpb.ListClustersRequest{
		Parent: "projects/" + kr.ProjectId + "/locations/-",
	})
	if err != nil {
		return nil, err
	}

	for _, c := range clusters.Clusters {
		if label != "" {
			if meshID == "" {
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
			ProjectId:       kr.ProjectId,
			ClusterName:     c.Name,
			ClusterLocation: c.Location,
			GKECluster:      c,
			KubeConfig:      addClusterConfig(c, kr.ProjectId, c.Location, c.Name),
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
