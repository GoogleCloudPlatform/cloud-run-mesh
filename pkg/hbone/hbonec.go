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
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// Client for mTLS-over-HTTP/2.
// Primarily for testing and for the CLI debug helper.
type HBoneClient struct {
	hb        *HBone
}

func (c HBoneClient) NewEndpoint(url string) *Endpoint {
	ep := c.hb.NewEndpoint(url)
	return ep
}

// Endpoint is a client for a specific destination.
type Endpoint struct {
	hb *HBone

	// URL used to reach the H2 endpoint providing the proxy.
	URL string

	// SNI name to use - defaults to service name
	SNI string

	// SNIGate is the endpoint address of a SNI gate. It can be a normal Istio SNI, a SNI to HBone or other protocols,
	// or a H2R gate.
	// If empty, the endpoint will use the URL and HBone protocol directly.
	// If set, the endpoint will use the nomal in-cluster Istio protocol.
	SNIGate string

	// H2Gate is the endpoint of a HTTP/2 gateway. Will be used to dial.
	// It is expected to have a spiffee identity, and request client certs -
	// similar with an egress gateway.
	H2Gate string

	tlsCon net.Conn
	rt     *http2.ClientConn // http.RoundTripper
}

func (hb *HBone) NewClient() *HBoneClient {
	return &HBoneClient{hb: hb}
}

// NewEndpoint creates a client for connecting to a specific service:port
//
// The service is mapped to an endpoint URL, protocol, etc. using a config callback,
// to isolate XDS or discovery dependency.
//
func (hb *HBone) NewEndpoint(urlOrHost string) *Endpoint {
	hc := &Endpoint{hb: hb}

	if !strings.HasPrefix(urlOrHost, "https://") {

		// TODO: for host and port - assume mTLS, using system certs for the 'external' tunnel
		// TODO: resolver call, to map to endpoint (including SNI routers or gateway)
		h, p, err := net.SplitHostPort(urlOrHost)
		if err == nil {
			urlOrHost = "https://" + h + "/_hbone/" + p
		}
		hc.URL = urlOrHost
	} else {
		hc.URL = urlOrHost
	}

	return hc
}

// Proxy will proxy in/out (plain text) to a remote service, using mTLS tunnel over H2 POST.
// used for testing.
func (hb *HBone) Proxy(svc string, hbURL string, stdin io.ReadCloser, stdout io.WriteCloser) error {
	c := hb.NewEndpoint(hbURL)
	return c.Proxy(context.Background(), stdin, stdout)
}

func (hc *Endpoint) Proxy(ctx context.Context, stdin io.Reader, stdout io.WriteCloser) error {
	if hc.SNIGate != "" {
		return hc.sniProxy(ctx, stdin, stdout)
	}

	t0 := time.Now()
	// It is usually possible to pass stdin directly to NewRequest.
	// Using a pipe allows getting stats.
	i, o := io.Pipe()
	defer stdout.Close()

	r, err := http.NewRequest("POST", hc.URL, i)
	if err != nil {
		return err
	}

	var rt = hc.rt

	if hc.hb.TokenCallback != nil {
		h := r.URL.Host
		if strings.Contains(h, ":") && h[0] != '[' {
			hn, _, _ := net.SplitHostPort(h)
			h = hn
		}
		t, err := hc.hb.TokenCallback(ctx, "https://"+h)
		if err != nil {
			log.Println("Failed to get token, attempt unauthenticated", err)
		} else {
			r.Header.Set("Authorization", "Bearer "+t)
		}
	}

	if hc.rt == nil {
		/* Alternative, using http.Client.
		  	ug = &http.Client{
				Transport: &http2.Transport{
					// So http2.Transport doesn't complain the URL scheme isn't 'https'
					AllowHTTP: true,
					// Pretend we are dialing a TLS endpoint.
					// Note, we ignore the passed tls.Config
					DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
						return net.Dial(network, addr)
					},
				},
			}
		*/
		h := r.URL.Host
		if hc.H2Gate != "" {
			h = hc.H2Gate
		}
		if Debug {
			rd, _ := httputil.DumpRequest(r, false)
			log.Println("HB req: ", h, string(rd))
		}
		host, port, _ := net.SplitHostPort(h)

		if r.URL.Scheme == "http" {
			d := &net.Dialer{}

			dialHost := r.URL.Host
			if port == "" {
				dialHost = net.JoinHostPort(dialHost, "80")
			}
			nConn, err := d.DialContext(ctx, "tcp", dialHost)
			if err != nil {
				return err
			}

			hc.tlsCon = nConn

		} else {
		// Expect system certificates.
			d := tls.Dialer{
				Config: &tls.Config{
					NextProtos: []string{"h2"},
				},
				NetDialer: &net.Dialer{},
			}
			dialHost := r.URL.Host
			if port == "" {
				dialHost = net.JoinHostPort(dialHost, "443")
			}
			if hc.H2Gate != "" {
				dialHost = hc.H2Gate
			}
			nConn, err := d.DialContext(ctx, "tcp", dialHost)
			if err != nil {
				return err
			}
			tlsCon := nConn.(*tls.Conn)

			tlsCon.VerifyHostname(host)

			if err != nil {
				return err
			}
			if tlsCon.ConnectionState().NegotiatedProtocol != "h2" {
				log.Println("Failed to negotiate h2", tlsCon.ConnectionState().NegotiatedProtocol)
				return errors.New("invalid ALPN protocol")
			}

			hc.tlsCon = tlsCon
		}

		rt, err = hc.hb.h2t.NewClientConn(hc.tlsCon)
		if err != nil {
			return err
		}

		hc.rt = rt
	}

	res, err := rt.RoundTrip(r)
	if err != nil {
		return err
	}

	t1 := time.Now()
	ch := make(chan int)
	var s1, s2 Stream

	s1 = Stream{
		ID:  "client-o",
		Dst: o,
		Src: stdin,
	}
	go s1.CopyBuffered(ch, true)

	s2 = Stream{
		ID:  "client-i",
		Dst: stdout,
		Src: res.Body,
	}
	s2.CopyBuffered(nil, true)

	<-ch

	log.Println("HBoneC-done", "url", r.URL, "status", res.Status, "conTime", t1.Sub(t0), "dur", time.Since(t1))
	if s2.Err != nil || s1.Err != nil || s2.InError || s1.InError {
		log.Println("HboneC close errors", s2.Err, s1.Err, s2.InError, s1.InError)
	}
	return s2.Err
}
