package meshconnectord

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"cloud.google.com/go/compute/metadata"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/gcp"
	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InitMeshEnvGCP updates the mesh env with GCP specific settings.
// This controller may run independently, in a GCP binary or in ASM.
func (sg *MeshConnector) InitMeshEnvGCP(ctx context.Context) error {
	kr := sg.Mesh
	var err error

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		// If not explicitly disabled, attempt to find MCP tenant ID and enable MCP
		if kr.MeshTenant != "-" {
			sg.FindTenant(ctx)
		}
		wg.Done()
	}()

	go func() {
		// If ProjectNumber used for P4SA not set, attempt to get it from ProjectID and fallback to metadata server
		if kr.ProjectNumber == "" && kr.ProjectId != "" {
			kr.ProjectNumber = gcp.ProjectNumber(kr.ProjectId)
		}
		if kr.ProjectNumber == ""  {
			// If project Id explicitly set, and not same as what metadata reports - fallback to getting it from GCP
			kr.ProjectNumber, _ = metadata.NumericProjectID()
		}
		wg.Done()
	}()

	wg.Wait()

	rootFile := filepath.Join(mesh.WorkloadCertDir, mesh.WorkloadRootCAs)
	rootCertPEM, err := ioutil.ReadFile(rootFile)
	if err == nil {
		sg.CAPool = sg.Mesh.Config("CAS_POOL", "")
		sg.CASRoots = string(rootCertPEM)
		log.Println("CASEnabled", "CAPool", sg.CAPool)
	}

	return err
}

// FindTenant will try to find the XDSAddr using in-cluster info.
// This is called after K8S client has been initialized.
//
// For MCP, will expect a config map named 'env-asm-managed'
// For in-cluster, we'll lookup the connector's LB, which points to istio.istio-system.svc
//
// This depends on MCP and Istiod internal configs - the config map may set with the XDS_ADDR and associated configs, in
// which case this will not be called.
func (sg *MeshConnector) FindTenant(ctx context.Context) error {
	kr := sg.Mesh
	if kr.ProjectNumber == "" {
		log.Println("MCP requires PROJECT_NUMBER, attempting to use in-cluster")
		return nil
	}
	cmname := os.Getenv("MCP_CONFIG")
	if cmname == "" {
		cmname = "env-asm-managed"
	}
	// TODO: find default tag, label, etc.
	// Current code is written for MCP, use XDS_ADDR explicitly
	// otherwise.
	s, err := sg.Client.CoreV1().ConfigMaps("istio-system").Get(ctx,
		cmname, metav1.GetOptions{})
	if err != nil {
		if Is404(err) {
			return nil
		}
		return err
	}

	kr.MeshTenant = s.Data["CLOUDRUN_ADDR"]
	log.Println("Istiod MCP discovered ", kr.MeshTenant, kr.XDSAddr,
		kr.ProjectId, kr.ProjectNumber, kr.TrustDomain)

	return nil
}


func Is404(err error) bool {
	if se, ok := err.(*errors.StatusError); ok {
		if se.ErrStatus.Code == 404 {
			return true
		}
	}
	return false
}

