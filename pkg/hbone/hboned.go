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
	Auth *Auth

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
func New(auth *Auth) *HBone {
	hb := &HBone{
		Auth: auth,
		Endpoints: map[string]*Endpoint{},
		H2R:       map[string]http.RoundTripper{},
		H2RConn: map[*http2.ClientConn]string{},
		TcpAddr:   "127.0.0.1:8080",
		h2t: &http2.Transport{
			ReadIdleTimeout: 10000 * time.Second,
			StrictMaxConcurrentStreams: false,
			AllowHTTP: true,

		},

		HTTPClientSystem: http.DefaultClient,
	}
	hb.h2t.ConnPool = hb
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



func (hb *HBone) HandleAcceptedH2(conn net.Conn) {
	conf := hb.Auth.MeshTLSConfig
	defer conn.Close()
	tls := tls.Server(conn, conf)

	// TODO: replace with handshake with context, timeout
	err := HandshakeTimeout(tls, hb.HandsahakeTimeout, conn)
	if err != nil {
		return
	}

	hb.HandleAcceptedH2C(tls)
}


func (hac *HBoneAcceptedConn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	defer func() {
		log.Println("Hbone", "", "", r, time.Since(t0))

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
	log.Println("HBD: ", r.RequestURI)
	w.(http.Flusher).Flush()

	// TCP proxy for SSH ( no mTLS, SSH has its own equivalent)
	if r.RequestURI ==  "/_hbone/22" {
		err := hac.hb.HandleTCPProxy(w, r.Body, "localhost:15022")
		log.Println("hbone proxy done ", r.RequestURI, err)

		return
	}
	if r.RequestURI ==  "/_hbone/tcp" {
		//w.Write([]byte{1})
		//w.(http.Flusher).Flush()

		err := hac.hb.HandleTCPProxy(w, r.Body, hac.hb.TcpAddr)
		log.Println("hbone proxy done ", r.RequestURI, err)

		return
	}
	if r.RequestURI ==  "/_hbone/mtls" {
		// Create a stream, used for proxy with caching.
		conf := hac.hb.Auth.MeshTLSConfig

		tls := tls.Server(&HTTPConn{r: r.Body, w: w,  acceptedConn: hac.conn}, conf)

		// TODO: replace with handshake with context
		err := HandshakeTimeout(tls, hac.hb.HandsahakeTimeout, nil)
		if err != nil {
			log.Println("HBD-MTLS: error inner mTLS ", err)
			return
		}
		log.Println("HBD-MTLS:", tls.ConnectionState())

		// TODO: All Istio checks go here. The TLS handshake doesn't check
		// root cert or anything - this is proof of concept only, to eval
		// perf.

		// TODO: allow user to customize app port, protocol.
		// TODO: if protocol is not matching wire protocol, convert.
		hac.hb.HandleTCPProxy(tls, tls, hac.hb.TcpAddr)
		//if tls.ConnectionState().NegotiatedProtocol == "h2" {
		//	// http2 and http expect a net.Listener, and do their own accept()
		//	hb.proxy.ServeConn(
		//		tls,
		//		&http2.ServeConnOpts{
		//			Handler: http.HandlerFunc(l.ug.H2Handler.httpHandleHboneCHTTP),
		//			Context: tc.Context(), // associated with the stream, with cancel
		//		})
		//} else {
		//	// HTTP/1.1
		//	// TODO. Typically we want to upgrade over the wire to H2
		//}
		return
	}

	rh, pat := hac.hb.Mux.Handler(r)
	if pat != "" {
		rh.ServeHTTP(w,r)
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
			Handler: hc,                   // Also plain text, needs to be upgraded
			Context: context.Background(),
			//Context can be used to cancel, pass meta.
			// h2 adds http.LocalAddrContextKey(NetAddr), ServerContextKey (*Server)
		})
}

// HandleTCPProxy connects and forwards r/w to the hostPort
func (hb *HBone) HandleTCPProxy(w io.Writer, r io.Reader, hostPort string) error {
	nc, err := net.Dial("tcp", hostPort)
	if err != nil {
		log.Println("Error dialing ", hostPort,err)
		return err
	}

	s1 := Stream{
		ID: "TCP-o",
		Dst: nc,
		Src: r,
	}
	ch := make(chan int)
	go s1.CopyBuffered(ch,true)

	s2 := Stream{
		ID: "TCP-i",
		Dst: w,
		Src: nc,
	}
	s2.CopyBuffered(nil, true)
	<- ch

	if s1.Err != nil {
		return s1.Err
	}
	if s2.Err != nil  {
		return s2.Err
	}

	return nil
}




