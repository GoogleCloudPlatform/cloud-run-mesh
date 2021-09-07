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

import _ "embed"

// TODO: this is only for testing hbone in envoy vs go. Will use the bootstrap file from docker image after testing is done.
// Also EnvoyFilters or server-side generated bootstrap could be used as well.

//go:embed envoy_bootstrap_tmpl.json
var EnvoyBootstrapTmpl string
