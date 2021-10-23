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

package sts

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
)

type cachedToken struct {
	token      string
	expiration time.Time
}

type TokenCache struct {
	cache sync.Map
	kr    *mesh.KRun
	sts   *STS
	m     sync.Mutex
}

func NewTokenCache(kr *mesh.KRun, sts *STS) *TokenCache {
	return &TokenCache{kr: kr, sts: sts}
}

func (c *TokenCache) Token(ctx context.Context, host string) (string, error) {
	if got, f := c.cache.Load(host); f {
		t := got.(cachedToken)
		if t.expiration.After(time.Now().Add(-time.Minute)) {
			return t.token, nil
		}
		log.Println("Token expired", t.expiration, time.Now(), host)
	}

	mt, err := c.sts.GetRequestMetadata(ctx, host)

	if err != nil {
		return "", err
	}
	bt := mt["authorization"]
	if !strings.HasPrefix(bt, "Bearer ") {
		return "", errors.New("Invalid prefix")
	}
	t := bt[7:]
	//log.Println("XXX debug Gettoken from metadata", host, k8s.TokenPayload(t), err)

	c.cache.Store(host, cachedToken{t, time.Now().Add(45 * time.Minute)})
	//log.Println("Storing JWT", host)
	return t, nil
}
