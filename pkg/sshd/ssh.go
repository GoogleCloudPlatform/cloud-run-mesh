//go:build !EXTERNAL_SSH
// +build !EXTERNAL_SSH

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

package sshd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

type Server struct {
	Port           int
	Shell          string
	AuthorizedKeys []gossh.PublicKey

	serverConfig *gossh.ServerConfig

	signer gossh.Signer

	// HandleConn can be used to overlay a SSH conn.

	CertChecker    *gossh.CertChecker
	Address        string
	Listener       net.Listener
	forwardHandler *ForwardedTCPHandler
}

func init() {
	inprocessInit = InitFromSecret
}

// InitFromSecret is a helper method to init the sshd using a secret or CA address
func InitFromSecret(sshCM map[string][]byte, ns string) {

	var signer gossh.Signer
	var r string

	sshCA := sshCM["SSHCA_ADDR"]

	var authKeys []gossh.PublicKey
	for k, v := range sshCM {
		if strings.HasPrefix(k, "authorized_key_") {
			pubk1, _, _, _, err := gossh.ParseAuthorizedKey(v)
			if err != nil {
				log.Println("SSH_DEBUG: invalid ", k, err)
			} else {
				authKeys = append(authKeys, pubk1)
				log.Println("Adding authorized key", k, string(v))
			}
		}
	}

	extra := os.Getenv("SSH_AUTH")
	if extra != "" {
		pubk1, _, _, _, err := gossh.ParseAuthorizedKey([]byte(extra))
		if err != nil {
			log.Println("SSH_DEBUG: invalid SSH_AUTH", err)
		} else {
			authKeys = append(authKeys, pubk1)
		}
	}

	if len(authKeys) == 0 && sshCA == nil {
		// No debug config, skip creating SSHD
		return
	}

	// load private key and cert from secret, if present
	ek := sshCM["id_ecdsa"]
	if ek != nil {
		pk, err := gossh.ParsePrivateKey(ek)
		if err != nil {
			log.Println("Failed to parse key ", err)
		}
		signer = pk
	}
	if signer == nil {
		privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		signer, _ = gossh.NewSignerFromKey(privk1)
	}

	ssht, err := NewSSHTransport(signer, "", ns, r)
	if err != nil {
		log.Println("SSH debug init failed", err)
		return
	}
	if len(authKeys) != 0 {
		ssht.AddAuthorizedKeys(authKeys)
	}
	go ssht.Start()

}

func NewSSHTransport(signer gossh.Signer, name, domain, root string) (*Server, error) {
	var pubk gossh.PublicKey
	var err error
	if root != "" {
		pubk, _, _, _, err = gossh.ParseAuthorizedKey([]byte(root))
		if err != nil {
			log.Println("No root CA key")
		}
	}

	shell := ""
	// Distroless + debug
	if _, err := os.Stat("/busybox/sh"); err == nil {
		shell = "/busybox/sh"
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		shell = "/bin/bash"
	}
	if _, err := os.Stat("/bin/sh"); err == nil {
		shell = "/bin/sh"
	}

	s := &Server{
		signer:       signer,
		serverConfig: &gossh.ServerConfig{},
		Port:         15022,
		Shell:        shell,
		// Server cert checker
		CertChecker: &gossh.CertChecker{
			IsUserAuthority: func(auth gossh.PublicKey) bool {
				if pubk == nil {
					return false
				}
				return KeysEqual(auth, pubk)
			},
		},
	}
	authorizedKeysBytes, err := ioutil.ReadFile(os.Getenv("HOME") + "/.ssh/authorized_keys")
	if err == nil {
		s.AddAuthorizedFile(authorizedKeysBytes)
	}

	if s.Address == "" {
		s.Address = ":15022"
	}

	s.forwardHandler = &ForwardedTCPHandler{}

	s.serverConfig.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if pubk != nil {
			p, err := s.CertChecker.Authenticate(conn, key)
			if err == nil {
				return p, nil
			}
		}
		if s.AuthorizedKeys != nil {
			for _, k := range s.AuthorizedKeys {
				if KeysEqual(key, k) {
					return &gossh.Permissions{}, nil
				}
			}
		}
		//log.Println("SSH auth failure", key, s.AuthorizedKeys)
		return nil, errors.New("SSH connection: no key found")
	}
	s.serverConfig.AddHostKey(signer)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	s.Listener, err = net.Listen("tcp", s.Address)
	if err != nil {
		log.Println("Failed to listend on ", s.Address, err)
		return nil, err
	}
	log.Println("SSHD listening on ", s.Address)

	return s, nil
}

func (s *Server) AddAuthorized(extra string) {
	pubk1, _, _, _, err := gossh.ParseAuthorizedKey([]byte(extra))
	if err == nil {
		s.AuthorizedKeys = append(s.AuthorizedKeys, pubk1)
	}
}

func (s *Server) AddAuthorizedFile(auth []byte) {
	for len(auth) > 0 {
		pubKey, _, _, rest, err := gossh.ParseAuthorizedKey(auth)
		if err != nil {
			return
		}

		s.AuthorizedKeys = append(s.AuthorizedKeys, pubKey)
		auth = rest
	}
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk gossh.PublicKey) bool {

	//avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

//func (srv *Server) getServer(signer ssh.Signer) *ssh.Server {
//	forwardHandler := &ssh.ForwardedTCPHandler{}
//
//	server := &ssh.Server{
//		ChannelHandlers: map[string]ssh.ChannelHandler{
//			"direct-tcpip": ssh.DirectTCPIPHandler,
//			"session":      ssh.DefaultSessionHandler,
//		},
//		RequestHandlers: map[string]ssh.RequestHandler{
//			"tcpip-forward":        forwardHandler.HandleSSHRequest,
//			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
//		},
//	}
//}

func (t *Server) Start() {
	go func() {
		for {
			nConn, err := t.Listener.Accept()
			if err != nil {
				log.Println("failed to accept incoming connection ", err)
				time.Sleep(10 * time.Second)
				continue
			}
			go t.HandleServerConn(nConn)
		}
	}()
}

// Handles a connection as SSH server, using a net.Conn - which might be tunneled over other transports.
// SSH handles multiplexing and packets.
func (sshGate *Server) HandleServerConn(nConn net.Conn) {
	// Before use, a handshake must be performed on the incoming
	// net.Conn. Handshake results in conn.Permissions.
	conn, chans, globalSrvReqs, err := gossh.NewServerConn(nConn, sshGate.serverConfig)
	if err != nil {
		nConn.Close()
		log.Println("SSHD: handshake error ", err, nConn.RemoteAddr())
		//sshGate.metrics.Errors.Add(1)
		return
	}
	log.Println("SSH connection from ", nConn.RemoteAddr())
	// TODO: track the session, for direct use

	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		conn.Close()
		cancel()
	}()

	go sshGate.handleServerConnRequests(ctx, globalSrvReqs, nConn, conn)

	// Service the incoming Channel channel.
	// Each channel is a stream - shell, exec, local TCP forward.
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			// When remote starts with a -L PORT:host:port, and connects to port
			var req channelOpenDirectMsg
			//scon.gate.localFwdS.Total.Add(1)
			err := gossh.Unmarshal(newChannel.ExtraData(), &req)
			if err != nil {
				log.Println("malformed-tcpip-request", err)
				newChannel.Reject(gossh.UnknownChannelType, "invalid data")
				continue
			}

			// TODO: allow connections to mesh VIPs
			//if role == ROLE_GUEST &&
			//		req.Rport != SSH_MESH_PORT && req.Rport != H2_MESH_PORT {
			//	newChannel.Reject(ssh.Prohibited,
			//		"only authorized users can proxy " +
			//				scon.VIP6.String())
			//	continue
			//}
			//log.Println("-L: forward request", req.Laddr, req.Lport, req.Raddr, req.Rport, role)

			go DirectTCPIPHandler(ctx, sshGate, conn, newChannel)
			//scon.handleDirectTcpip(newChannel, req.Raddr, req.Rport, req.Laddr, req.Lport)
			//conId++

		case "session":
			// session channel - the main interface for shell, exec
			ch, reqs, _ := newChannel.Accept()
			// Used for messages.
			s := &session{
				Channel: ch,
				conn:    conn,
				srv:     sshGate,
			}
			go s.handleRequests(reqs)

		default:
			fmt.Println("SSHD: unknown channel Rejected", newChannel.ChannelType())
			newChannel.Reject(gossh.UnknownChannelType, "unknown channel type")
		}
	}

}

// Global requests
func (scon *Server) handleServerConnRequests(ctx context.Context, reqs <-chan *gossh.Request, nConn net.Conn, conn *gossh.ServerConn) {
	for r := range reqs {
		// Global types.
		switch r.Type {
		// "-R": we expect at least one R with 0.0.0.0 and port 5222, corresponding to the main mux dispatcher.
		// SSHClientConn clients will only accept back connections with this particular host:port, and srcIP:srcPort.
		// Other reverse accept ports can be opened as well.
		case "tcpip-forward":
			var req tcpipForwardRequest
			err := gossh.Unmarshal(r.Payload, &req)
			if err != nil {
				log.Println("malformed-tcpip-request", err)
				r.Reply(false, nil)
				continue
			}

			go scon.forwardHandler.HandleSSHRequest(ctx, scon, r, conn)

			continue

		case "keepalive@openssh.com":
			//n.LastSeen = time.Now()
			//log.Println("SSHD: client keepalive", n.VIP)
			r.Reply(true, nil)

		default:
			log.Println("SSHD: unknown global REQUEST ", r.Type)
			if r.WantReply {
				log.Println(r.Type)
				r.Reply(false, nil)
			}
		}
	}
}

func (srv *Server) AddAuthorizedKeys(keys []gossh.PublicKey) {
	for _, k := range keys {
		srv.AuthorizedKeys = append(srv.AuthorizedKeys, k)
	}
}

type execRequest struct {
	Command string
}

type tcpipForwardRequest struct {
	BindIP   string
	BindPort uint32
}

type tcpipForwardResponse struct {
	BoundPort uint32
}

// "forwarded-tcp" or "-R" - reverse, ssh-server-accepted connections sent to client.
// VPN or public device will expose a port, or a dmesh client will use a local port as Gateway
// ForwardIP/ForwardPort are used as keys - to match the listener.
type forwardTCPIPChannelRequest struct {
	ForwardIP   string
	ForwardPort uint32
	OriginIP    string
	OriginPort  uint32
}

// RFC 4254 7.2 - direct-tcpip
// -L or -D, or egress. Client using VPN as an egress gateway.
// Raddr can be a string (hostname) or IP.
// Laddr is typically 127.0.0.1 (unless ssh has an open socks, and other machines use it)
//
type channelOpenDirectMsg struct {
	Raddr string
	Rport uint32

	Laddr string
	Lport uint32
}
