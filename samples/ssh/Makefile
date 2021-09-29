
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
OUT?=${ROOT_DIR}/../../../out/krun

# Helper to create a secret for the debug endpoint.
#
# WIP: alternative is to deploy a SSH cert authoritiy in the config cluster, will be
# auto-detected and used.

init-keys:
	mkdir -p ${OUT}/ssh
	(cd ${OUT}/ssh; ssh-keygen -t ecdsa -f id_ecdsa -N "")
	cp ${HOME}/.ssh/id_ecdsa.pub ${OUT}/ssh/authorized_keys

WORKLOAD_NAMESPACE?=default

secret: init-keys
	kubectl -n ${WORKLOAD_NAMESPACE} delete secret sshdebug || true
	kubectl -n ${WORKLOAD_NAMESPACE} create secret generic \
 		sshdebug \
 		--from-file=authorized_key_${USER}=${OUT}/ssh/authorized_keys \
 		--from-file=id_ecdsa=${OUT}/ssh/id_ecdsa \
 		--from-file=id_ecdsa.pub=${OUT}/ssh/id_ecdsa.pub
	rm -rf ${OUT}/ssh

# SSH to the deployed CloudRun using HBONE
ssh: CR_URL=$(shell gcloud run services describe ${SERVICE} --format="value(status.address.url)")
ssh:
	 ssh -F /dev/null -v \
        -o StrictHostKeyChecking=no -o "UserKnownHostsFile /dev/null" \
 	    -o ProxyCommand='hbone ${CR_URL}:443/_hbone/22' \
     	root@proxybase ${SSH_ARGS}

config_dump: CR_URL=$(shell gcloud run services describe ${SERVICE} --format="value(status.address.url)")
config_dump:
	 ssh -F /dev/null -o StrictHostKeyChecking=no \
        -o "UserKnownHostsFile /dev/null" \
 	    -o ProxyCommand='hbone ${CR_URL}/_hbone/22' -- sh curl localhost:15000/config_dump
