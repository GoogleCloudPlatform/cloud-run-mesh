module github.com/GoogleCloudPlatform/cloud-run-mesh/meshcon

go 1.16

replace github.com/GoogleCloudPlatform/cloud-run-mesh => ../
require (
	github.com/GoogleCloudPlatform/cloud-run-mesh v0.0.0-20211003154220-58e3fc8e81fa
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
)
