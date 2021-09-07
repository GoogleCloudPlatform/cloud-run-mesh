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

package uk8s

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
)

// WIP - removing the dep on k8s client library for the 2 bootstrap requests needed
// (get mesh-env and tokens).

// uK8S is a micro client for K8S, intended for bootstraping and minimal
// config.
///
// uK8S implements read access to K8S API servier using http requests
// It only supports GET - primarily to download the mesh-env config map,
// and the TokenRequest API needed for tokens/certificates.

// Based on/inspired from kelseyhightower/konfig

//
// It uses JWT tokens for auth, with the default credentials, and supports
// basic resources used for bootstrap. It is not intended for watching resources
// or complicated operations (list, write), only quick get of few configmaps, secret, services
//
// Refactored/extacted from 'konfig'

// Copyright 2019 The Konfig Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.


type Secret struct {
	ApiVersion string            `json:"apiVersion"`
	Data       map[string]string `json:"data"`
	Kind       string            `json:"kind"`
}

type ConfigMap struct {
	ApiVersion string            `json:"apiVersion"`
	Data       map[string]string `json:"data"`
	Kind       string            `json:"kind"`
}

type CreateTokenResponseStatus struct {
	Token       string            `json:"token"`
}

type CreateTokenRequestSpec struct {
	Audiences       []string            `json:"audiences"`
}

type CreateTokenRequest struct {
	Spec       CreateTokenRequestSpec            `json:"spec"`
}

type CreateTokenResponse struct {
	Status       CreateTokenResponseStatus            `json:"status"`
}

var (
	projectName    = "konfig"
	projectVersion = "0.1.0"
	projectURL     = "https://github.com/costinm/konfig"
	userAgent      = fmt.Sprintf("%s/%s (+%s; %s)",
		projectName, projectVersion, projectURL, runtime.Version())
)

// UK8S is a micro k8s client, using only base http and a token source.
type UK8S struct {
	Client   *http.Client
	ProjectID string
	Base     string
	Name     string
	Id       string
	Location string
	Token    string
}

func (uK8S *UK8S) String() string {
	return uK8S.Id
}

func (uK8S *UK8S) GetSecret(ns, name string) (*Secret, error) {
	data, err := uK8S.GetResource(ns, "secret", name, nil)
	if err != nil {
		return nil, err
	}
	var secret Secret
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func (uK8S *UK8S) GetConfigMap(ns, name string) (*ConfigMap, error) {
	data, err := uK8S.GetResource(ns, "configmap", name, nil)
	if err != nil {
		return nil, err
	}
	var secret ConfigMap
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func (uK8S *UK8S) GetToken(ns, name, aud string) (*ConfigMap, error) {
	data, err := uK8S.GetResource(ns, "serviceaccount", name+"/token", nil)
	if err != nil {
		return nil, err
	}
	var secret ConfigMap
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func (uk8s *UK8S) GetResource(ns, kind, name string, postdata []byte) ([]byte, error) {

	resourceURL := uk8s.Base + fmt.Sprintf("/api/v1/namespaces/%s/%ss/%s",
		ns, kind, name)

	//log.Println(resourceURL)
	var resp *http.Response
	var err error
	var req *http.Request
	if postdata == nil {
		req, _ = http.NewRequest("GET", resourceURL, nil)
	} else {
		req, _ := http.NewRequest("POST", resourceURL, bytes.NewReader(postdata))
		req.Header.Add("content-type", "application/json")
	}
	if uk8s.Token != "" {
		req.Header.Add("authorization", "bearer " + uk8s.Token)
	}
	resp, err = uk8s.Client.Do(req)

	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("kconfig: unable to get %s.%s %s from Kubernetes status code %v",
			ns, name, kind, resp.StatusCode))
	}

	return data, nil
}


