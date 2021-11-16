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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// HBone represents a node using a HTTP/2 or HTTP/3 based overlay network environment.
//
// Each HBone node has a Istio (spiffee) certificate.
//
// HBone can be used as a client, server or gateway.
type HBone struct {
	h2Server *http2.Server
	Cert     *tls.Certificate
	rp       *httputil.ReverseProxy

	// Non-local endpoints. Key is the 'pod id' of a H2R client
	Endpoints map[string]*Endpoint

	// H2R holds H2 client (reverse) connections to the local server.
	// Will be used to route requests directly. Key is the SNI expected in forwarding requests.
	H2R map[string]http.RoundTripper

	h2rListener net.Listener
	sniListener net.Listener
	h2t         *http2.Transport

	SNIAddr string

	HTTPClientSystem *http.Client
	HTTPClientMesh   *http.Client
	TcpAddr          string

	// Ports is the equivalent of container ports in k8s.
	// Name follows the same conventions as Istio and should match the port name in the Service.
	// Port "*" means 'any' port - if set, allows connections to any port by number.
	// Currently this is loaded from env variables named PORT_name=value, with the default PORT_http=8080
	// TODO: refine the 'wildcard' to indicate http1/2 protocol
	// TODO: this can be populated from a WorkloadGroup object, loaded from XDS or mesh env.
	Ports map[string]string

	TokenCallback func(ctx context.Context, host string) (string, error)
	Mux           http.ServeMux

	// Timeout used for TLS handshakes. If not set, 3 seconds is used.
	HandsahakeTimeout time.Duration

	EndpointResolver func(sni string) *Endpoint

	m           sync.RWMutex
	H2RConn     map[*http2.ClientConn]string
	H2RCallback func(string, *http2.ClientConn)
}

// New creates a new HBone node. It requires a workload identity, including mTLS certificates.
func New() *HBone {
	// Need to set this to allow timeout on the read header
	h1 := &http.Transport{
		ExpectContinueTimeout: 3 * time.Second,
	}
	h2, _ := http2.ConfigureTransports(h1)
	h2.ReadIdleTimeout = 10 * time.Minute // TODO: much larger to support long-lived connections
	h2.AllowHTTP = true
	h2.StrictMaxConcurrentStreams = false
	hb := &HBone{
		Endpoints: map[string]*Endpoint{},
		H2R:       map[string]http.RoundTripper{},
		H2RConn:   map[*http2.ClientConn]string{},
		TcpAddr:   "127.0.0.1:8080",
		h2t:       h2,
		Ports: 		 map[string]string{},
		//&http2.Transport{
		//	ReadIdleTimeout: 10000 * time.Second,
		//	StrictMaxConcurrentStreams: false,
		//	AllowHTTP: true,
		//},

		HTTPClientSystem: http.DefaultClient,
	}
	//hb.h2t.ConnPool = hb
	hb.h2Server = &http2.Server{}

	u, _ := url.Parse("http://127.0.0.1:8080")
	hb.rp = httputil.NewSingleHostReverseProxy(u)

	return hb
}

type HBoneAcceptedConn struct {
	hb   *HBone
	conn net.Conn
}

// StartBHoneD will listen on addr as H2C (typically :15009)
//
//
// Incoming streams for /_hbone/mtls will be treated as a mTLS connection,
// using the Istio certificates and root. After handling mTLS, the clear text
// connection will be forwarded to localhost:8080 ( TODO: custom port ).
//
// TODO: setting for app protocol=h2, http, tcp - initial impl uses tcp
//
// Incoming requests for /_hbone/22 will be forwarded to localhost:22, for
// debugging with ssh.
//

func (hac *HBoneAcceptedConn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	var proxyErr error
	defer func() {
		log.Println(r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, time.Since(t0), proxyErr)

		if r := recover(); r != nil {
			fmt.Println("Recovered in hbone", r)

			debug.PrintStack()

			// find out exactly what the error was and set err
			var err error

			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
			if err != nil {
				fmt.Println("ERRROR: ", err)
			}
		}
	}()

	// TODO: parse Envoy / hbone headers.
	w.(http.Flusher).Flush()

	// TCP proxy for SSH ( no mTLS, SSH has its own equivalent)
	if r.RequestURI == "/_hbone/22" {
		proxyErr = hac.hb.HandleTCPProxy(w, r.Body, "localhost:15022")
		return
	}
	if r.RequestURI == "/_hbone/15003" {
		proxyErr = hac.hb.HandleTCPProxy(w, r.Body, "localhost:15003")
		return
	}
	if r.RequestURI == "/_hbone/tcp" {
		proxyErr = hac.hb.HandleTCPProxy(w, r.Body, hac.hb.TcpAddr)
		return
	}

	rh, pat := hac.hb.Mux.Handler(r)
	if pat != "" {
		rh.ServeHTTP(w, r)
		return
	}

	// This is not a tunnel, but regular request. For test only - should be off once mTLS
	// works properly.
	hac.hb.rp.ServeHTTP(w, r)
}

func (hb *HBone) HandleAcceptedH2C(conn net.Conn) {
	hc := &HBoneAcceptedConn{hb: hb, conn: conn}
	hb.h2Server.ServeConn(
		conn,
		&http2.ServeConnOpts{
			Handler: hc, // Also plain text, needs to be upgraded
			Context: context.Background(),
			//Context can be used to cancel, pass meta.
			// h2 adds http.LocalAddrContextKey(NetAddr), ServerContextKey (*Server)
		})
}

// HandleTCPProxy connects and forwards r/w to the hostPort
func (hb *HBone) HandleTCPProxy(w io.Writer, r io.Reader, hostPort string) error {
	nc, err := net.Dial("tcp", hostPort)
	if err != nil {
		log.Println("Error dialing ", hostPort, err)
		return err
	}

	s1 := Stream{
		ID:  "TCP-o",
		Dst: nc,
		Src: r,
	}
	ch := make(chan int)
	go s1.CopyBuffered(ch, true)

	s2 := Stream{
		ID:  "TCP-i",
		Dst: w,
		Src: nc,
	}
	s2.CopyBuffered(nil, true)
	<-ch

	if s1.Err != nil {
		return s1.Err
	}
	if s2.Err != nil {
		return s2.Err
	}

	return nil
}
