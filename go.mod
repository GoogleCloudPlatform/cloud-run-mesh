module github.com/costinm/cloud-run-mesh

go 1.16

//replace github.com/costinm/hbone => ../hbone
//replace github.com/costinm/cert-ssh/ssh => ../cert-ssh/ssh

require (
	cloud.google.com/go v0.84.0
	github.com/costinm/cert-ssh/ssh v0.0.0-20210825233239-a732a424ec23
	github.com/creack/pty v1.1.13
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.1.2
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/api v0.48.0
	google.golang.org/genproto v0.0.0-20210608205507-b6d2f5bf0d7d
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
	k8s.io/klog v1.0.0
)
