package main

import (
	"context"

	"github.com/costinm/cert-ssh/ssh"
	"github.com/costinm/cloud-run-mesh/pkg/mesh"
)

// Optional debug dependency, using cert-based SSH or loaded from a secret.
// TODO: add conditional compilation, or move it to a separate binary that can be forked

func init() {
	initDebug = InitDebug
}

func InitDebug(kr *mesh.KRun) {
	sshCM, _ := kr.GetSecret(context.Background(), kr.Namespace, "sshdebug")

	ssh.InitFromSecret(sshCM, kr.Namespace)
}
