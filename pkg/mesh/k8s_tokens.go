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
	"errors"
)


// RequireTranportSecurity is part of gRPC interface, returning false because we also support secure networks (low-level)
func (kr *KRun) RequireTransportSecurity() bool {
	return false
}

// GetRequestMetadata implements credentials.PerRPCCredentials with normal audience semantics, returning tokens signed
// by K8S APIserver. For GCP tokens, use 'sts' package.
func (kr *KRun) GetRequestMetadata(ctx context.Context, aud ...string) (map[string]string, error) {
	a0 := ""
	if len(aud) > 0 {
		a0 = aud[0]
	}
	if len(aud) > 1 {
		return nil, errors.New("Single audience supporte")
	}
	kt, err := kr.GetToken(ctx, a0)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + kt,
	}, nil
}

// GetToken returns a token with the given audience for the current KSA, using CreateToken request.
// Used by the STS token exchanger.
func (kr *KRun) GetToken(ctx context.Context, aud string) (string, error) {
	return kr.TokenProvider.GetToken(ctx, aud)
}

