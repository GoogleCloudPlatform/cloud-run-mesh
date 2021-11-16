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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/cloud-run-mesh/pkg/mesh"
	"golang.org/x/oauth2"
)

// From nodeagent/plugin/providers/google/stsclient
// In Istio, the code is used if "GoogleCA" is set as CA_PROVIDER or CA_ADDR has the right prefix
var (
	// SecureTokenEndpoint is the Endpoint the STS client calls to.
	SecureTokenEndpoint = "https://sts.googleapis.com/v1/token"

	httpTimeout         = time.Second * 5
	contentType         = "application/json"
	Scope               = "https://www.googleapis.com/auth/cloud-platform"
	accessTokenEndpoint = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	idTokenEndpoint     = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"

	// Server side
	// TokenPath is url path for handling STS requests.
	TokenPath = "/token"
	// StsStatusPath is the path for dumping STS status.
	StsStatusPath = "/stsStatus"
	// URLEncodedForm is the encoding type specified in a STS request.
	URLEncodedForm = "application/x-www-form-urlencoded"
	// TokenExchangeGrantType is the required value for "grant_type" parameter in a STS request.
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	// SubjectTokenType is the required token type in a STS request.
	SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"

	Debug = false
)

// error code sent in a STS error response. A full list of error code is
// defined in https://tools.ietf.org/html/rfc6749#section-5.2.
const (
	// If the request itself is not valid or if either the "subject_token" or
	// "actor_token" are invalid or unacceptable, the STS server must set
	// error code to "invalid_request".
	invalidRequest = "invalid_request"
	// If the authorization server is unwilling or unable to issue a token, the
	// STS server should set error code to "invalid_target".
	invalidTarget      = "invalid_target"
	stsIssuedTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

// STS provides token exchanges. Implements grpc and golang.org/x/oauth2.TokenSource
// The source of trust is the K8S token with TrustDomain audience, it is exchanged with access or ID tokens.
type STS struct {
	httpClient *http.Client
	kr         *mesh.KRun
}

func NewSTS(kr *mesh.KRun) (*STS, error) {
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	return &STS{
		kr: kr,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		},
	}, nil
}

// Implements oauth2.TokenSource
func (s *STS) Token() (*oauth2.Token, error) {

	return nil, nil
}

// GetRequestMetadata implements credentials.PerRPCCredentials
// This can be used for both ID tokens or access tokens - if the 'aud' containts googleapis.com, access tokens are returned.
func (s *STS) GetRequestMetadata(ctx context.Context, aud ...string) (map[string]string, error) {
	kt, err := s.kr.GetToken(ctx, s.kr.TrustDomain)
	if err != nil {
		return nil, err
	}
	ft, err := s.TokenFederated(ctx, kt)
	if err != nil {
		return nil, err
	}
	a0 := ""
	if len(aud) > 0 {
		a0 = aud[0]
	}
	if len(aud) > 1 {
		return nil, errors.New("Single audience supporte")
	}

	if strings.Contains(a0, "googleapis.com/") {
		return map[string]string{
			"authorization": "Bearer " + ft,
		}, nil
	}

	token, err := s.TokenAccess(ctx, ft, a0)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": "Bearer " + token,
	}, nil
}

func (s *STS) RequireTransportSecurity() bool {
	return false
}

// TokenFederated exchanges the K8S JWT with a federated token
// (former ExchangeToken)
func (s *STS) TokenFederated(ctx context.Context, k8sSAjwt string) (string, error) {
	stsAud := s.constructAudience("", s.kr.TrustDomain)
	jsonStr, err := s.constructFederatedTokenRequest(stsAud, k8sSAjwt)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federated token request: %v", err)
	}

	req, err := http.NewRequest("POST", SecureTokenEndpoint, bytes.NewBuffer(jsonStr))
	req = req.WithContext(ctx)

	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %v, (aud: %s, STS endpoint: %s)", err, stsAud, SecureTokenEndpoint)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("token exchange read failed: %v, (aud: %s, STS endpoint: %s)", err, stsAud, SecureTokenEndpoint)
	}
	respData := &federatedTokenResponse{}
	if err := json.Unmarshal(body, respData); err != nil {
		// Normally the request should json - extremely hard to debug otherwise, not enough info in status/err
		log.Println("Unexpected unmarshal error, response was ", string(body))
		return "", fmt.Errorf("(aud: %s, STS endpoint: %s), failed to unmarshal response data of size %v: %v",
			stsAud, SecureTokenEndpoint, len(body), err)
	}

	if respData.AccessToken == "" {
		return "", fmt.Errorf(
			"exchanged empty token (aud: %s, STS endpoint: %s), response: %v", stsAud, SecureTokenEndpoint, string(body))
	}

	return respData.AccessToken, nil
}

func (s *STS) TokenAccess(ctx context.Context, federatedToken string, audience string) (string, error) {
	req, err := s.constructGenerateAccessTokenRequest(federatedToken, audience)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federated token request: %v", err)
	}
	req = req.WithContext(ctx)
	res, err := s.httpClient.Do(req)

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %v", err)
	}

	if audience == "" {
		respData := &accessTokenResponse{}

		if err := json.Unmarshal(body, respData); err != nil {
			// Normally the request should json - extremely hard to debug otherwise, not enough info in status/err
			log.Println("Unexpected unmarshal error, response was ", string(body))
			return "", fmt.Errorf("failed to unmarshal response data of size %v: %v",
				len(body), err)
		}

		if respData.AccessToken == "" {
			return "", fmt.Errorf(
				"exchanged empty token, response: %v", string(body))
		}

		return respData.AccessToken, nil
	}
	respData := &idTokenResponse{}

	if err := json.Unmarshal(body, respData); err != nil {
		// Normally the request should json - extremely hard to debug otherwise, not enough info in status/err
		log.Println("Unexpected unmarshal error, response was ", string(body))
		return "", fmt.Errorf("failed to unmarshal response data of size %v: %v",
			len(body), err)
	}

	if respData.Token == "" {
		return "", fmt.Errorf(
			"exchanged empty token, response: %v", string(body))
	}

	return respData.Token, nil
}

type federatedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"` // Expiration time in seconds
}

// provider can be extracted from metadata server, or is set using GKE_ClusterURL
//
// For VMs, it is set as GoogleComputeEngine via CREDENTIAL_IDENTITY_PROVIDER env
// In Istio GKE it is constructed from metadata, on VM it is GKE_CLUSTER_URL or gcp_gke_cluster_url,
// format "https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s" - this also happens to be
// the 'iss' field in the token.
// According to docs, aud can be:
// iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/<pool-id>/providers/<provider-id>.
// or gcloud URL
// Required when exchanging an external credential for a Google access token.
func (s *STS) constructAudience(provider, trustDomain string) string {
	if provider == "" {
		provider = s.kr.ClusterAddress
	}
	return fmt.Sprintf("identitynamespace:%s:%s", trustDomain, provider)
}

// fetchFederatedToken exchanges a third-party issued Json Web Token for an OAuth2.0 access token
// which asserts a third-party identity within an identity namespace.
func (s *STS) constructFederatedTokenRequest(aud, jwt string) ([]byte, error) {
	values := map[string]string{
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange", // fixed, no options
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"audience":           aud, // full name if the identity provider.
		"subjectToken":       jwt,
		"scope":              Scope, // required for the GCP exchanges
	}

	// golang sts also includes:
	jsonValue, err := json.Marshal(values)
	return jsonValue, err
}

// from security/security.go

// StsRequestParameters stores all STS request attributes defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.1
type StsRequestParameters struct {
	// REQUIRED. The value "urn:ietf:params:oauth:grant-type:token- exchange"
	// indicates that a token exchange is being performed.
	GrantType string
	// OPTIONAL. Indicates the location of the target service or resource where
	// the client intends to use the requested security token.
	Resource string
	// OPTIONAL. The logical name of the target service where the client intends
	// to use the requested security token.
	Audience string
	// OPTIONAL. A list of space-delimited, case-sensitive strings, that allow
	// the client to specify the desired Scope of the requested security token in the
	// context of the service or Resource where the token will be used.
	Scope string
	// OPTIONAL. An identifier, for the type of the requested security token.
	RequestedTokenType string
	// REQUIRED. A security token that represents the identity of the party on
	// behalf of whom the request is being made.
	SubjectToken string
	// REQUIRED. An identifier, that indicates the type of the security token in
	// the "subject_token" parameter.
	SubjectTokenType string
	// OPTIONAL. A security token that represents the identity of the acting party.
	ActorToken string
	// An identifier, that indicates the type of the security token in the
	// "actor_token" parameter.
	ActorTokenType string
}

// From stsservice/sts.go

// StsResponseParameters stores all attributes sent as JSON in a successful STS
// response. These attributes are defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.1
type StsResponseParameters struct {
	// REQUIRED. The security token issued by the authorization server
	// in response to the token exchange request.
	AccessToken string `json:"access_token"`
	// REQUIRED. An identifier, representation of the issued security token.
	IssuedTokenType string `json:"issued_token_type"`
	// REQUIRED. A case-insensitive value specifying the method of using the access
	// token issued. It provides the client with information about how to utilize the
	// access token to access protected resources.
	TokenType string `json:"token_type"`
	// RECOMMENDED. The validity lifetime, in seconds, of the token issued by the
	// authorization server.
	ExpiresIn int64 `json:"expires_in"`
	// OPTIONAL, if the Scope of the issued security token is identical to the
	// Scope requested by the client; otherwise, REQUIRED.
	Scope string `json:"scope"`
	// OPTIONAL. A refresh token will typically not be issued when the exchange is
	// of one temporary credential (the subject_token) for a different temporary
	// credential (the issued token) for use in some other context.
	RefreshToken string `json:"refresh_token"`
}

// From tokenexchangeplugin.go
type Duration struct {
	// Signed seconds of the span of time. Must be from -315,576,000,000
	// to +315,576,000,000 inclusive. Note: these bounds are computed from:
	// 60 sec/min * 60 min/hr * 24 hr/day * 365.25 days/year * 10000 years
	Seconds int64 `json:"seconds"`
}

type accessTokenRequest struct {
	Name      string   `json:"name"` // nolint: structcheck, unused
	Delegates []string `json:"delegates"`
	Scope     []string `json:"scope"`
	LifeTime  Duration `json:"lifetime"` // nolint: structcheck, unused
}

type idTokenRequest struct {
	Audience     string   `json:"audience"` // nolint: structcheck, unused
	Delegates    []string `json:"delegates"`
	IncludeEmail bool     `json:"includeEmail"`
}

type accessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

type idTokenResponse struct {
	Token string `json:"token"`
}

// constructFederatedTokenRequest returns an HTTP request for access token.
// Example of an access token request:
// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/
// service-<GCP project number>@gcp-sa-meshdataplane.iam.gserviceaccount.com:generateAccessToken
// Content-Type: application/json
// Authorization: Bearer <federated token>
// {
//  "Delegates": [],
//  "Scope": [
//      https://www.googleapis.com/auth/cloud-platform
//  ],
// }
func (s *STS) constructGenerateAccessTokenRequest(fResp string, audience string) (*http.Request, error) {
	gsa := "service-" + s.kr.ProjectNumber + "@gcp-sa-meshdataplane.iam.gserviceaccount.com"
	endpoint := ""
	var err error
	var jsonQuery []byte
	if audience == "" {
		endpoint = fmt.Sprintf(accessTokenEndpoint, gsa)
		// Request for access token with a lifetime of 3600 seconds.
		query := accessTokenRequest{
			LifeTime: Duration{Seconds: 3600},
		}
		query.Scope = append(query.Scope, Scope)

		jsonQuery, err = json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal query for get access token request: %+v", err)
		}
	} else {
		endpoint = fmt.Sprintf(idTokenEndpoint, gsa)
		// Request for access token with a lifetime of 3600 seconds.
		query := idTokenRequest{
			IncludeEmail: true,
			Audience:     audience,
		}

		jsonQuery, err = json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal query for get access token request: %+v", err)
		}
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create get access token request: %+v", err)
	}
	req.Header.Add("Content-Type", contentType)
	if Debug {
		reqDump, _ := httputil.DumpRequest(req, true)
		log.Println("Prepared access token request: ", string(reqDump))
	}
	req.Header.Add("Authorization", "Bearer "+fResp) // the AccessToken
	return req, nil
}

// ServeStsRequests handles STS requests and sends exchanged token in responses.
func (s *STS) ServeStsRequests(w http.ResponseWriter, req *http.Request) {
	reqParam, validationError := s.validateStsRequest(req)
	if validationError != nil {
		// If request is invalid, the error code must be "invalid_request".
		// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
		s.sendErrorResponse(w, invalidRequest, validationError)
		return
	}
	// We start with reqParam.SubjectToken - loaded from the file by the client.
	// Must be a K8S Token with right trust domain
	ft, err := s.TokenFederated(req.Context(), reqParam.SubjectToken)
	if err != nil {
		s.sendErrorResponse(w, invalidTarget, err)
		return
	}

	at, err := s.TokenAccess(req.Context(), ft, "")

	if err != nil {
		log.Printf("token manager fails to generate token: %v", err)
		// If the authorization server is unable to issue a token, the "invalid_target" error code
		// should be used in the error response.
		// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
		s.sendErrorResponse(w, invalidTarget, err)
		return
	}
	s.sendSuccessfulResponse(w, s.generateSTSRespInner(at))
}

func (p *STS) generateSTSRespInner(token string) []byte {
	//exp, err := time.Parse(time.RFC3339Nano, atResp.ExpireTime)
	// Default token life time is 3600 seconds
	var expireInSec int64 = 3600
	//if err == nil {
	//	expireInSec = int64(time.Until(exp).Seconds())
	//}
	stsRespParam := StsResponseParameters{
		AccessToken:     token,
		IssuedTokenType: stsIssuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       expireInSec,
	}
	statusJSON, _ := json.MarshalIndent(stsRespParam, "", " ")
	return statusJSON
}

// validateStsRequest validates a STS request, and extracts STS parameters from the request.
func (s *STS) validateStsRequest(req *http.Request) (StsRequestParameters, error) {
	reqParam := StsRequestParameters{}
	if req == nil {
		return reqParam, errors.New("request is nil")
	}

	//if stsServerLog.DebugEnabled() {
	//	reqDump, _ := httputil.DumpRequest(req, true)
	//	stsServerLog.Debugf("Received STS request: %s", string(reqDump))
	//}
	if req.Method != "POST" {
		return reqParam, fmt.Errorf("request method is invalid, should be POST but get %s", req.Method)
	}
	if req.Header.Get("Content-Type") != URLEncodedForm {
		return reqParam, fmt.Errorf("request content type is invalid, should be %s but get %s", URLEncodedForm,
			req.Header.Get("Content-type"))
	}
	if parseErr := req.ParseForm(); parseErr != nil {
		return reqParam, fmt.Errorf("failed to parse query from STS request: %v", parseErr)
	}
	if req.PostForm.Get("grant_type") != TokenExchangeGrantType {
		return reqParam, fmt.Errorf("request query grant_type is invalid, should be %s but get %s",
			TokenExchangeGrantType, req.PostForm.Get("grant_type"))
	}
	// Only a JWT token is accepted.
	if req.PostForm.Get("subject_token") == "" {
		return reqParam, errors.New("subject_token is empty")
	}
	if req.PostForm.Get("subject_token_type") != SubjectTokenType {
		return reqParam, fmt.Errorf("subject_token_type is invalid, should be %s but get %s",
			SubjectTokenType, req.PostForm.Get("subject_token_type"))
	}
	reqParam.GrantType = req.PostForm.Get("grant_type")
	reqParam.Resource = req.PostForm.Get("resource")
	reqParam.Audience = req.PostForm.Get("audience")
	reqParam.Scope = req.PostForm.Get("scope")
	reqParam.RequestedTokenType = req.PostForm.Get("requested_token_type")
	reqParam.SubjectToken = req.PostForm.Get("subject_token")
	reqParam.SubjectTokenType = req.PostForm.Get("subject_token_type")
	reqParam.ActorToken = req.PostForm.Get("actor_token")
	reqParam.ActorTokenType = req.PostForm.Get("actor_token_type")
	return reqParam, nil
}

// StsErrorResponse stores all Error parameters sent as JSON in a STS Error response.
// The Error parameters are defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
type StsErrorResponse struct {
	// REQUIRED. A single ASCII Error code.
	Error string `json:"error"`
	// OPTIONAL. Human-readable ASCII [USASCII] text providing additional information.
	ErrorDescription string `json:"error_description"`
	// OPTIONAL. A URI identifying a human-readable web page with information
	// about the Error.
	ErrorURI string `json:"error_uri"`
}

// sendErrorResponse takes error type and error details, generates an error response and sends out.
func (s *STS) sendErrorResponse(w http.ResponseWriter, errorType string, errDetail error) {
	w.Header().Add("Content-Type", "application/json")
	if errorType == invalidRequest {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	errResp := StsErrorResponse{
		Error:            errorType,
		ErrorDescription: errDetail.Error(),
	}
	if errRespJSON, err := json.MarshalIndent(errResp, "", "  "); err == nil {
		if _, err := w.Write(errRespJSON); err != nil {
			return
		}
	} else {
		log.Printf("failure in marshaling error response (%v) into JSON: %v", errResp, err)
	}
}

// sendSuccessfulResponse takes token data and generates a successful STS response, and sends out the STS response.
func (s *STS) sendSuccessfulResponse(w http.ResponseWriter, tokenData []byte) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(tokenData); err != nil {
		log.Printf("failure in sending STS success response: %v", err)
		return
	}
}
