# STS  (secure token service) client and server code

Extracted from Istio repository and cleaned up. The intent is to include it directly in the krun/hbone, to avoid
requiring pilot-agent for proxyless gRPC and 'uProxy' hbone mode.

STS is defined in RFC6750. Istio client is in stsclient.go (used for MeshCA) and tokenexchangeplugin.go.

Golang gRPC has credentials/sts/sts.go - unfortunately the API requires the token to be saved to a path

Stackdriver uses a similar STS exchange, implemented in Envoy, with STS server in istio-agent, using:

```json
 {
        "stackdriver_grpc_service": {
        "google_grpc": {
          "stat_prefix": "oc_stackdriver_tracer",
          "channel_credentials": {
            "ssl_credentials": {
              "root_certs": {
                "filename": "/etc/ssl/certs/ca-certificates.crt"
              }
            }
          },
          "call_credentials": {
            "sts_service": {
              "token_exchange_service_uri": "http://localhost:{{ .stsPort }}/token",
              "subject_token_path": "/var/run/secrets/tokens/istio-token",
              "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
              "scope": "https://www.googleapis.com/auth/cloud-platform",
            }
          }
        },
        "initial_metadata": [
          {
            "key": "x-goog-user-project",
            "value": "{{ .gcp_project_id }}"
          }
        ]
      },
}
```

## Generate access/ID token

[generateAccessToken](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken)

Requires 'iam.serviceAccounts.getAccessToken' permission or roles/iam.serviceAccountTokenCreator
