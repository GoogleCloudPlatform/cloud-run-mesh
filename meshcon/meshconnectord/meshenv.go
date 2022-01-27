package meshconnectord

import (
	"context"
	"log"
	"sync"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InitMeshEnv updates a config map containing env variables that customize the mesh agent.
// It is NOT USER FACING - controllers create it and patch it.
// The main rule is that unknown fields are left alone, and only specific fields are reconciled.
func (sg *MeshConnector) InitMeshEnv(ctx context.Context) error {
	kr := sg.Mesh
	var err error

	wq := sync.WaitGroup{}
	wq.Add(1)

	// Discover the citadel root. Will be saved along with other discovered root CAs.
	// Citadel root is used for the XDS server, if in-cluster OSS Istio is used and citadel
	// enabled.
	go func() {
		defer wq.Done()
		citadelRoot, e := sg.GetCitadelRoots(ctx)
		if err != nil {
			err = e
			return
		}
		if citadelRoot != "" {
			kr.CitadelRoot = citadelRoot
		}
	}()

	wq.Wait()

	return err
}

// Load the CA roots from istio-ca-root-cert configmap in istio-system.
// This is typically replicated in each namespace and mounted - but we'll not rely on this, just make mesh-env
// readable to all authenticated users.
// This is used to connect to Istiod, and is typically the Citadel root CA. If missing, it means citadel is not used
// and CAS will be used instead.
//
// Mesh connector will use the mesh roots.
func (sg *MeshConnector) GetCitadelRoots(ctx context.Context) (string, error) {
	// TODO: depending on error, move on or report a real error
	kr := sg.Mesh
	cm, err := kr.Cfg.GetCM(ctx, "istio-system", "istio-ca-root-cert")
	if err != nil {
		if Is404(err) {
			return "", nil
		}
		return "", err
	} else {
		// normally mounted to /var/run/secrets/istio
		rootCert := cm["root-cert.pem"]
		if rootCert == "" {
			return "", nil
		} else {
			return rootCert, nil
		}
	}
}

func (sg *MeshConnector) updateMeshEnv(ctx context.Context) error {
	cmAPI := sg.Client.CoreV1().ConfigMaps(sg.Namespace)
	cm, err := cmAPI.Get(ctx, "mesh-env", metav1.GetOptions{})
	if err != nil {
		if !Is404(err) {
			return err
		}
		// Not found, create:
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mesh-env",
				Namespace: "istio-system",
			},
			Data: map[string]string{},
		}
		sg.SaveToMap(sg.Mesh, cm.Data)
		_, err = cmAPI.Create(ctx, cm, metav1.CreateOptions{})
		if err != nil {
			log.Println("Failed to update config map, skipping ", err)
		}
		return nil
	}

	if !sg.SaveToMap(sg.Mesh, cm.Data) {
		return nil
	}
	_, err = cmAPI.Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		log.Println("Failed to update config map, skipping ", err)
	} else {
		log.Println("Update mesh env with defaults")
	}
	return nil
}

// Internal implementation detail for the 'mesh-env' for Istio and MCP.
// This may change, it is not a stable API - see loadMeshEnv for the other side.
//
// Note that XDS_ADDR is not included by default - workloads will use the (I)MCON_ADDR
// or MCP if MESH_TENANT is set. TD will also be set automatically if ASM clusters are not
// detected.
func (sg *MeshConnector) SaveToMap(kr *mesh.KRun, d map[string]string) bool {
	needUpdate := false

	// Set the GCP specific options, extracted from metadata - if not already set.
	needUpdate = setIfEmpty(d, "PROJECT_NUMBER", kr.ProjectNumber, needUpdate)
	needUpdate = setIfEmpty(d, "PROJECT_ID", kr.ProjectId, needUpdate)

	// If "-" or empty - MCP is not available in the config cluster, will use the mesh gateway.
	needUpdate = setIfEmpty(d, "MESH_TENANT", kr.MeshTenant, needUpdate)

	needUpdate = setIfEmpty(d, "CLUSTER_NAME", kr.ClusterName, needUpdate)
	needUpdate = setIfEmpty(d, "CLUSTER_LOCATION", kr.ClusterLocation, needUpdate)

	// Public and internal address of the mesh connector. Internal only available in GKE and similar
	// clusters.
	needUpdate = setIfEmpty(d, "MCON_ADDR", kr.MeshConnectorAddr, needUpdate)
	needUpdate = setIfEmpty(d, "IMCON_ADDR", kr.MeshConnectorInternalAddr, needUpdate)

	// TODO: set CAS based on the WorkloadCertificate config - for now use the default name if Zatar is enabled
	// This should set the full config - including EC support, etc.
	needUpdate = setIfEmpty(d, "CA_POOL", sg.CAPool, needUpdate)
	needUpdate = setIfEmpty(d, "CAROOT_CAS", sg.CASRoots, needUpdate)


	if kr.CitadelRoot != "" {
		// CA root of the XDS server. Empty if only MeshCA is used.
		// TODO: use CAROOT_XXX to save multiple CAs (MeshCA, Citadel, other clusters)
		needUpdate = setIfEmpty(d, "CAROOT_ISTIOD", kr.CitadelRoot, needUpdate)
	}

	return needUpdate
}

func setIfEmpty(d map[string]string, key, val string, upd bool) bool {
	if d[key] == "" && val != "" {
		d[key] = val
		return true
	}
	return upd
}


