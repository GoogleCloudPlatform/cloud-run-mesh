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
	"strings"
	"time"
)

// Will start a SNI proxy, similar with Istio East-West or Gateway SNI router.
// Accepted connections will decode the ServerName header, and use it to forward to either a HBONE
// mTLS service or a H2R connection.


func (hc *Endpoint) sniProxy(ctx context.Context, stdin io.Reader, stdout io.WriteCloser) error {
	d := net.Dialer{} // TODO: customizations

	conn, err := d.DialContext(ctx, "tcp", hc.SNIGate)
	if Debug {
		log.Println("sniProxyC: ", conn.RemoteAddr(), hc.URL, hc.SNIGate)
	}
	if err != nil {
		return err
	}

	// Using the low-level interface, to keep control over TLS.
	conf := &tls.Config{}
	conf.ServerName = hc.SNI

	defer conn.Close()

	tlsCon := tls.Client(conn, conf)
	err = HandshakeTimeout(tlsCon, hc.hb.HandsahakeTimeout, nil)
	if err != nil {
		return err
	}

	return proxy(ctx, stdin, stdout, tlsCon, tlsCon)
}

func (hb *HBone) HandleSNIConn(conn net.Conn) {
	s := NewBufferReader(conn)
	// will also close the conn ( which is the reader )
	defer s.Close()

	sni, err := ParseTLS(s)
	if err != nil {
		log.Println("SNI invalid TLS", sni, err)
		return
	}

	// Based on SNI, make a hbone request, using JWT auth.
	if hb.EndpointResolver != nil {
		dst := hb.EndpointResolver(sni)
		if dst != nil {
			if Debug {
				log.Println("SNI: start proxy", "sni", sni, "URL", dst.URL)
			}
			t0 := time.Now()
			err = dst.Proxy(context.Background(), s, conn)
			if err != nil {
				log.Println("SNI: error connecting to proxy", "sni", sni, "error", err, "URL", dst.URL)
			} else {
				log.Println("SNI:done", "sni", sni, "URL", dst.URL, "dur", time.Since(t0))
			}
		} else {
			log.Println("SNI: Missing destination", "sni", sni)
		}
	} else {
		log.Println("SNI: Missing EndpointResolver", "sni", sni)
	}
}

var sniErr = errors.New("Invalid TLS")

type ClientHelloMsg struct { // 22
	vers uint16
	//random              []byte
	sessionId []byte
	//CipherSuites        []uint16
	//compressionMethods  []uint8
	ServerName string
	//ocspStapling        bool
	//scts                bool
	//supportedPoints     []uint8
	//ticketSupported     bool
	//sessionTicket       []uint8
	//secureRenegotiation []byte
}

// TLS extension numbers
const (
	extensionServerName uint16 = 0
)

// TODO: if a session ID is provided, use it as a cookie and attempt
// to find the corresponding host.
// On server side generate session IDs !
//
// TODO: in mesh, use one cypher suite (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
// maybe 2 ( since keys are ECDSA )
func ParseTLS(acc *BufferReader) (string, error) {
	buf, err := acc.Fill(5)
	if err != nil {
		return "", err
	}
	typ := buf[0] // 22 3 1 2 0
	if typ != 0x16 {
		return "", sniErr
	}
	vers := uint16(buf[1])<<8 | uint16(buf[2])
	if vers != 0x301 {
		log.Println("Version ", vers)
	}

	rlen := int(buf[3])<<8 | int(buf[4])
	if rlen > 16*1024 {
		log.Println("RLen ", rlen)
		return "", sniErr
	}

	off := 5
	m := ClientHelloMsg{}

	end := rlen + 5
	buf, err = acc.Fill(end)
	if err != nil {
		return "", err
	}
	clientHello := buf[5:end]
	chLen := end - 5

	if chLen < 38 {
		log.Println("chLen ", chLen)
		return "", sniErr
	}

	// off is the last byte in the buffer - will be forwarded

	m.vers = uint16(clientHello[4])<<8 | uint16(clientHello[5])
	// random: data[6:38]

	sessionIdLen := int(clientHello[38])
	if sessionIdLen > 32 || chLen < 39+sessionIdLen {
		log.Println("sLen ", sessionIdLen)
		return "", sniErr
	}
	m.sessionId = clientHello[39 : 39+sessionIdLen]
	off = 39 + sessionIdLen

	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(clientHello[off])<<8 | int(clientHello[off+1])
	off += 2
	if cipherSuiteLen%2 == 1 || chLen-off < 2+cipherSuiteLen {
		return "", sniErr
	}

	//numCipherSuites := cipherSuiteLen / 2
	//m.cipherSuites = make([]uint16, numCipherSuites)
	//for i := 0; i < numCipherSuites; i++ {
	//	m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	//}
	off += cipherSuiteLen

	compressionMethodsLen := int(clientHello[off])
	off++
	if chLen-off < 1+compressionMethodsLen {
		return "", sniErr
	}
	//m.compressionMethods = data[1 : 1+compressionMethodsLen]
	off += compressionMethodsLen

	if off+2 > chLen {
		// ClientHello is optionally followed by extension data
		return "", sniErr
	}

	extensionsLength := int(clientHello[off])<<8 | int(clientHello[off+1])
	off = off + 2
	if extensionsLength != chLen-off {
		return "", sniErr
	}

	for off < chLen {
		extension := uint16(clientHello[off])<<8 | uint16(clientHello[off+1])
		off += 2
		length := int(clientHello[off])<<8 | int(clientHello[off+1])
		off += 2
		if off >= end {
			return "", sniErr
		}

		switch extension {
		case extensionServerName:
			d := clientHello[off : off+length]
			if len(d) < 2 {
				return "", sniErr
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return "", sniErr
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return "", sniErr
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return "", sniErr
				}
				if nameType == 0 {
					m.ServerName = string(d[:nameLen])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(m.ServerName, ".") {
						return "", sniErr
					}
					break
				}
				d = d[nameLen:]
			}
		default:
			//log.Println("TLS Ext", extension, length)
		}

		off += length
	}

	// Does not contain port !!! Assume the port is 443, or map it.

	// TODO: unmangle server name - port, mesh node

	return m.ServerName, nil
}
