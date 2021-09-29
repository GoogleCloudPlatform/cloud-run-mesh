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

package hbone

import (
	"context"
	"net/url"
	"sync"
	"time"
)

// Using the same model as k8s.io/client-go/tools/metrics

// DurationMetric is a measurement of some amount of time.
type DurationMetric interface {
	Observe(duration time.Duration)
}

// LatencyMetric observes client latency partitioned by verb and url.
type LatencyMetric interface {
	Observe(ctx context.Context, verb string, u url.URL, latency time.Duration)
}

// ResultMetric counts response codes partitioned by method and host.
type ResultMetric interface {
	Increment(ctx context.Context, code string, method string, host string)
}

var (
	// RequestLatency is the latency metric that rest clients will update.
	RequestLatency LatencyMetric = noopLatency{}
	// RequestResult is the result metric that rest clients will update.
	RequestResult ResultMetric = noopResult{}
)

// RegisterOpts contains all the metrics to register. Metrics may be nil.
type RegisterOpts struct {
	RequestLatency LatencyMetric
	RequestResult  ResultMetric
}

var registerMetrics sync.Once

// Register registers metrics for the rest client to use. This can
// only be called once.
func Register(opts RegisterOpts) {
	registerMetrics.Do(func() {
		if opts.RequestLatency != nil {
			RequestLatency = opts.RequestLatency
		}
		if opts.RequestResult != nil {
			RequestResult = opts.RequestResult
		}
	})
}

type noopDuration struct{}

func (noopDuration) Observe(time.Duration) {}

type noopExpiry struct{}

func (noopExpiry) Set(*time.Time) {}

type noopLatency struct{}

func (noopLatency) Observe(context.Context, string, url.URL, time.Duration) {}

type noopResult struct{}

func (noopResult) Increment(context.Context, string, string, string) {}

type noopCalls struct{}

func (noopCalls) Increment(int, string) {}
