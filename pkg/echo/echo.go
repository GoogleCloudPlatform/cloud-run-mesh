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

package echo

import (
	"bytes"
	"log"
	"net"
	"time"
)

type EchoHandler struct {
	Debug       bool
	ServerFirst bool
	WaitFirst   time.Duration

	Received int
}

func (e *EchoHandler) handle(str net.Conn) {
	d := make([]byte, 2048)

	//si := GetStreamInfo(str)
	//si.RemoteID=   RemoteID(str)
	//b1, _ := json.Marshal(si)

	if e.Debug {
		log.Println("Echo ", e.ServerFirst, str.RemoteAddr())
	}
	b := &bytes.Buffer{}
	b.WriteString("Hello world\n")
	//b.Write(b1)
	//b.Write([]byte{'\n'})

	time.Sleep(e.WaitFirst)

	if e.ServerFirst {
		n, err := str.Write(b.Bytes())
		if e.Debug {
			log.Println("ServerFirst write()", n, err)
		}
	}
	//ac.SetDeadline(time.Now().StartListener(5 * time.Second))

	writeClosed := false
	for {
		n, err := str.Read(d)
		e.Received += n
		if e.Debug {
			log.Println("Echo read()", n, err)
		}
		if err != nil {
			if e.Debug {
				log.Println("ECHO DONE")
			}
			str.Close()
			return
		}
		if d[0] == 0 {
			if wc, ok := str.(interface {
				CloseWrite() error
			}); ok {
				wc.CloseWrite()
				writeClosed = true
				// Continue to read ! The test can check the read byte counts
			}
		}

		if !writeClosed {
			// TODO: add delay (based on req)
			str.Write(d[0:n])
			if e.Debug {
				log.Println("ECHO write")
			}
		}
	}
}

func (e *EchoHandler) Start(s string) (net.Listener, error) {
	el, err := net.Listen("tcp", s)
	if err != nil {
		return nil, err
	}
	go e.serve(el, e.handle)
	return el, nil
}

func (hb *EchoHandler) serve(l net.Listener, f func(conn net.Conn)) {
	for {
		remoteConn, err := l.Accept()
		if ne, ok := err.(net.Error); ok {
			if ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		if err != nil {
			log.Println("Accept error, closing listener ", err)
			return
		}

		go f(remoteConn)
	}
}
