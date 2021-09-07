package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/costinm/cloud-run-mesh/pkg/gcp"
	"github.com/costinm/cloud-run-mesh/pkg/hbone"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
)

var initDebug func(run *mesh.KRun)

func main() {
	kr := mesh.New("")

	kr.VendorInit = gcp.InitGCP

	err := kr.LoadConfig(context.Background())
	if err != nil {
		log.Fatal("Failed to connect to mesh ", time.Since(kr.StartTime), kr, os.Environ(), err)
	}

	log.Println("K8S Client initialized", kr.ProjectId, kr.ClusterLocation, kr.ClusterName, kr.ProjectNumber,
		kr.KSA, kr.Namespace, kr.Name, kr.Labels, kr.XDSAddr)


	kr.RefreshAndSaveFiles()

	meshMode := true

	if _, err := os.Stat("/usr/local/bin/pilot-agent"); os.IsNotExist(err) {
		meshMode = false
	}
	if kr.XDSAddr == "-" {
		meshMode = false
	}

	if meshMode {
		// Use k8s client to autoconfigure, reading from cluster.
		err := kr.StartIstioAgent()
		if err != nil {
			log.Fatal("Failed to start the mesh agent ", err)
		}
		// TODO: wait for proxy ready before starting app.
	}

	kr.StartApp()

	// Start internal SSH server, for debug and port forwarding. Can be conditionally compiled.
	if initDebug != nil {
		// Split for conditional compilation (to compile without ssh dep)
		initDebug(kr)
	}

	// TODO: wait for app and proxy ready

	if meshMode {
		auth, err := hbone.NewAuthFromDir("")
		if err != nil {
			log.Fatal("Failed to find mesh certificates ", err)
		}
		auth.AddRoots([]byte(gcp.MeshCA))

		hb := hbone.New(auth)
		_, err = hbone.ListenAndServeTCP(":15009", hb.HandleAcceptedH2C)
		if err != nil {
			log.Fatal("Failed to start h2c on 15009", err)
		}

		// if hgate east-west gateway present, create a connection.
		hg, err := kr.FindHGate(context.Background())
		if err != nil || hg == "" {
			log.Println("hgate not found, not attaching to the cluster", err)
		} else {
			attachC := hb.NewClient(kr.Name + "." + kr.Namespace + ":15009")
			attachE := attachC.NewEndpoint("")
			attachE.SNI = fmt.Sprintf("outbound_.8080_._.%s.%s.svc.cluster.local", kr.Name, kr.Namespace)
			go func() {
				_, err := attachE.DialH2R(context.Background(), hg+":15441")
				log.Println("H2R connected", hg, err)
			}()
		}

	}
	select {}
}
