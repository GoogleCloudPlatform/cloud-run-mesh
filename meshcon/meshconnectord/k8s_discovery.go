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

package meshconnectord

import (
	"context"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
)

// On client connection, create a WorkloadEntry or EndpointSlice so
// Istio is able to connect using the gateway IP and SNI port.

// Implementation notes:
// For WorkloadEntry, Istio name is based on group-ip0-network, truncated to 253
// (workloadentry_controller.go), using AUTO_REGISTER_GROUP meta.
//
//

func (sg *MeshConnector) UpdateSlice(ctx context.Context, kr *mesh.KRun, ns string,
	name string) {
	es := &discoveryv1.EndpointSlice{}
	sg.Client.DiscoveryV1().EndpointSlices(ns).Get(
		ctx, name, metav1.GetOptions{})
	sg.Client.DiscoveryV1().EndpointSlices(ns).Create(
		ctx, es, metav1.CreateOptions{})
	sg.Client.DiscoveryV1().EndpointSlices(ns).Update(
		ctx, es, metav1.UpdateOptions{})
}

type EventHandler struct {
	sg *MeshConnector
}

func (e EventHandler) OnAdd(obj interface{}) {
	if sv, ok := obj.(*corev1.Service); ok {
		e.sg.Services[sv.Name + "." + sv.Namespace] = sv
		return
	}
	if es, ok := obj.(*discoveryv1.EndpointSlice); ok {
		// Example:
		//&EndpointSlice{
		//ObjectMeta:{fortio-canary-lvm4m fortio-canary- fortio  5ce098ab-968d-41d7-925c-dd0dd6230c70 259977129 9 2021-08-24 18:42:23 -0700 PDT <nil> <nil>
		// map[endpointslice.kubernetes.io/managed-by:endpointslice-controller.k8s.io kubernetes.io/service-name:fortio-canary]
		//map[endpoints.kubernetes.io/last-change-trigger-time:2021-08-30T15:57:19Z] [{v1 Service fortio-canary 30d6f4f1-c47c-4338-9198-390be715091c 0xc0004e9e97 0xc0004e9e98}] []  [{kube-controller-manager Update discovery.k8s.io/v1beta1 2021-08-30 08:57:21 -0700 PDT FieldsV1 {"f:addressType":{},"f:endpoints":{},"f:metadata":{"f:annotations":{".":{},"f:endpoints.kubernetes.io/last-change-trigger-time":{}},"f:generateName":{},"f:labels":{".":{},"f:endpointslice.kubernetes.io/managed-by":{},"f:kubernetes.io/service-name":{}},"f:ownerReferences":{".":{},"k:{\"uid\":\"30d6f4f1-c47c-4338-9198-390be715091c\"}":{".":{},"f:apiVersion":{},"f:blockOwnerDeletion":{},"f:controller":{},"f:kind":{},"f:name":{},"f:uid":{}}}},"f:ports":{}}}]},
		//
		//Endpoints:[]
		//  Endpoint{Endpoint{
		//    Addresses:[10.4.9.15],
		//    Conditions:EndpointConditions{Ready:*true,Serving:nil,Terminating:nil,},
		//    Hostname:nil,
		//    TargetRef:
		//      &v1.ObjectReference{
		//          Kind:Pod,
		//          Namespace:fortio,
		//          Name:fortio-canary-5f6d5b9758-m7m94,
		//          UID:c64385b5-6492-4452-b0b9-99e7a0b69f45,
		//          APIVersion:,
		//          ResourceVersion:259977127,FieldPath:,},
		//     Topology:map[string]string{
		//        kubernetes.io/hostname: gke-istio-pool-1-7b5d72e3-q6oq,
		//        topology.kubernetes.io/region: us-central1,
		//        topology.kubernetes.io/zone: us-central1-c,},
		//      NodeName:nil,
		//      Hints:nil,},},
		//
		//Ports:[]
		//  EndpointPort{EndpointPort{Name:*http,Protocol:*TCP,Port:*8080,AppProtocol:nil,},
		//  EndpointPort{Name:*grpc,Protocol:*TCP,Port:*8081,AppProtocol:nil,},},
		//AddressType:IPv4,}

		e.sg.EP[es.Name + "." + es.Namespace] = es
		return
	}
}

func (e EventHandler) OnUpdate(oldObj, obj interface{}) {
	if sv, ok := obj.(*corev1.Service); ok {
		e.sg.Services[sv.Name + "." + sv.Namespace] = sv
		return
	}
	if es, ok := obj.(*discoveryv1.EndpointSlice); ok {
		e.sg.EP[es.Name + "." + es.Namespace] = es
		return
	}
}

func (e EventHandler) OnDelete(obj interface{}) {
	if sv, ok := obj.(*corev1.Service); ok {
		delete(e.sg.Services, sv.Name + "." + sv.Namespace)
		return
	}
	if es, ok := obj.(*discoveryv1.EndpointSlice); ok {
		delete(e.sg.EP, es.Name + "." + es.Namespace)
		return
	}
}

func (sg *MeshConnector) NewWatcher() {

	inF := informers.NewSharedInformerFactory(sg.Client, 0)
	eh := &EventHandler{sg: sg}

	// WIP - need to figure out which version, someone complains.
	//inF.Discovery().V1().EndpointSlices().Informer().AddEventHandler(eh)

	svci := inF.Core().V1().Services().Informer()

	svci.AddEventHandler(eh)

	go inF.Start(sg.stop)

	//go esi.Run(sg.stop)

}
