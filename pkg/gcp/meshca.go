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

package gcp

import _ "embed"

// This contains the long-lived MeshCA key. Used for migrations, if the
// key is not configured in cluster.

// Since the caller may connect to clusters with either Citadel or MeshCA, and
// communicate with workloads in different clusters, we need to configure both.

//go:embed meshca.pem
var MeshCA string
