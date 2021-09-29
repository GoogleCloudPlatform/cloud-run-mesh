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

package mesh

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Read with Secrets and ConfigMaps

func (kr *KRun) GetCM(ctx context.Context, ns string, name string) (map[string]string, error) {
	s, err := kr.Client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return map[string]string{}, err
	}

	return s.Data, nil
}

func (kr *KRun) GetSecret(ctx context.Context, ns string, name string) (map[string][]byte, error) {
	s, err := kr.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if Is404(err) {
			err = nil
		}
		return map[string][]byte{}, err
	}

	return s.Data, nil
}
