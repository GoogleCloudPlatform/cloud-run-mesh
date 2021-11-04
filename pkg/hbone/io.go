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
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TODO: benchmark different sizes.
var bufSize = 32 * 1024
var Debug = false

var (
	// createBuffer to get a buffer. io.Copy uses 32k.
	// experimental use shows ~20k max read with Firefox.
	bufferPoolCopy = sync.Pool{New: func() interface{} {
		return make([]byte, 0, 32*1024)
	}}
)

// CloseWriter is one of possible interfaces implemented by Out to send a FIN, without closing
// the input. Some writers only do this when Close is called.
type CloseWriter interface {
	CloseWrite() error
}

var streamIDs int64 = 0

type Stream struct {
	Written int64
	Err     error
	InError bool

	Src io.Reader
	Dst io.Writer
	ID  string
}

func proxy(ctx context.Context, cin io.Reader, cout io.WriteCloser, sin io.Reader, sout io.WriteCloser) error {
	ch := make(chan int)
	s1 := Stream{
		ID:  "client-o",
		Dst: sout,
		Src: cin,
	}
	go s1.CopyBuffered(ch, true)

	s2 := Stream{
		ID:  "client-i",
		Dst: cout,
		Src: sin,
	}
	s2.CopyBuffered(nil, true)
	<-ch
	if s1.Err != nil {
		return s1.Err
	}
	return s2.Err
}

// CopyBuffered will copy src to dst, using a pooled intermediary buffer.
//
// Blocking, returns when src returned an error or EOF/graceful close.
// May also return with error if src or dst return errors.
//
// CopyBuffered may be called in a go routine, for one of the streams in the
// connection - the stats and error are returned on a channel.
func (s Stream) CopyBuffered(ch chan int, close bool) {
	buf1 := bufferPoolCopy.Get().([]byte)
	defer bufferPoolCopy.Put(buf1)
	bufCap := cap(buf1)
	buf := buf1[0:bufCap:bufCap]

	//st := Stream{}

	// For netstack: src is a gonet.Conn, doesn't implement WriterTo. Dst is a net.TcpConn - and implements ReadFrom.
	// CopyBuffered is the actual implementation of Copy and CopyBuffer.
	// if buf is nil, one is allocated.
	// Duplicated from io

	// This will prevent stats from working.
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	//if wt, ok := src.(io.WriterTo); ok {
	//	return wt.WriteTo(dst)
	//}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	//if rt, ok := dst.(io.ReaderFrom); ok {
	//	return rt.ReadFrom(src)
	//}
	if ch != nil {
		defer func() {
			ch <- int(0)
		}()
	}
	if s.ID == "" {
		s.ID = strconv.Itoa(int(atomic.AddInt64(&streamIDs, 1)))
	}
	if Debug {
		log.Println(s.ID, "startCopy()")
	}
	for {
		if srcc, ok := s.Src.(net.Conn); ok {
			srcc.SetReadDeadline(time.Now().Add(15 * time.Minute))
		}
		nr, er := s.Src.Read(buf)
		if Debug {
			log.Println(s.ID, "read()", nr, er)
		}
		if nr > 0 { // before dealing with the read error
			nw, ew := s.Dst.Write(buf[0:nr])
			if Debug {
				log.Println(s.ID, "write()", nw, ew)
			}
			if nw > 0 {
				s.Written += int64(nw)
			}
			if f, ok := s.Dst.(http.Flusher); ok {
				f.Flush()
			}
			if nr != nw { // Should not happen
				ew = io.ErrShortWrite
				if Debug {
					log.Println(s.ID, "write error - short write", s.Err)
				}
			}
			if ew != nil {
				s.Err = ew
				return
			}
		}
		if er != nil {
			if strings.Contains(er.Error(), "NetworkIdleTimeout") {
				er = io.EOF
			}
			if er == io.EOF {
				if Debug {
					log.Println(s.ID, "done()")
				}
			} else {
				s.Err = er
				s.InError = true
				if Debug {
					log.Println(s.ID, "readError()", s.Err)
				}
			}
			if close {
				// read is already closed - we need to close out
				closeWriter(s.Dst)
			}
			return
		}
	}
}

func closeWriter(dst io.Writer) error {
	if cw, ok := dst.(CloseWriter); ok {
		return cw.CloseWrite()
	}
	if c, ok := dst.(io.Closer); ok {
		return c.Close()
	}
	if rw, ok := dst.(http.ResponseWriter); ok {
		// Server side HTTP stream. For client side, FIN can be sent by closing the pipe (or
		// request body). For server, the FIN will be sent when the handler returns - but
		// this only happen after request is completed and body has been read. If server wants
		// to send FIN first - while still reading the body - we are in trouble.

		// That means HTTP2 TCP servers provide no way to send a FIN from server, without
		// having the request fully read.

		// This works for H2 with the current library - but very tricky, if not set as trailer.
		rw.Header().Set("X-Close", "0")
		rw.(http.Flusher).Flush()
		return nil
	}
	log.Println("Server out not Closer nor CloseWriter nor ResponseWriter", dst)
	return nil
}

// HTTPConn wraps a http server request/response in a net.Conn
type HTTPConn struct {
	r            io.Reader
	w            io.Writer
	acceptedConn net.Conn
}

func (hc *HTTPConn) Read(b []byte) (n int, err error) {
	return hc.r.Read(b)
}

// Write wraps the writer, which can be a http.ResponseWriter.
// Will make sure Flush() is called - normal http is buffering.
func (hc *HTTPConn) Write(b []byte) (n int, err error) {
	n, err = hc.w.Write(b)
	if f, ok := hc.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

func (hc *HTTPConn) Close() error {
	// TODO: close write
	if cw, ok := hc.w.(CloseWriter); ok {
		return cw.CloseWrite()
	}
	log.Println("Unexpected writer not implement CloseWriter")
	return nil
}

func (hc *HTTPConn) LocalAddr() net.Addr {
	return hc.acceptedConn.LocalAddr()
}

func (hc *HTTPConn) RemoteAddr() net.Addr {
	return hc.acceptedConn.RemoteAddr()
}

func (hc *HTTPConn) SetDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (hc *HTTPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// HandshakeTimeout wraps tlsConn.Handshake with a timeout, to prevent hanging connection.
func HandshakeTimeout(tlsConn *tls.Conn, d time.Duration, plainConn net.Conn) error {
	errc := make(chan error, 2)
	var timer *time.Timer // for canceling TLS handshake
	if d == 0 {
		d = 3 * time.Second
	}
	timer = time.AfterFunc(d, func() {
		errc <- tlsHandshakeTimeoutError{}
	})
	go func() {
		err := tlsConn.Handshake()
		if timer != nil {
			timer.Stop()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		if plainConn != nil {
			plainConn.Close()
		} else {
			tlsConn.Close()
		}
		return err
	}
	return nil
}

func ListenAndServeTCP(addr string, f func(conn net.Conn)) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go ServeListener(listener, f)
	return listener, nil
}

func ServeListener(l net.Listener, f func(conn net.Conn)) error {
	for {
		remoteConn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(interface {
				Temporary() bool
			}); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// TODO: callback to notify. This may happen if interface restarts, etc.
			log.Println("Accepted done ", l)
			return err
		}

		go f(remoteConn)
	}
}

// BufferReader wraps a buffer and a Reader.
// The Fill method will populate the buffer.
// Read will first return data from the buffer, and if buffer is empty will
// read directly from the source reader.
type BufferReader struct {
	buf        []byte
	roff, rend int
	Reader     io.Reader
}

func NewBufferReader(in io.Reader) *BufferReader {
	buf1 := bufferPoolCopy.Get().([]byte)
	return &BufferReader{buf: buf1, Reader: in}
}

func (s *BufferReader) Fill(i int) ([]byte, error) {
	if s.rend >= i {
		return s.buf[0:s.rend], nil
	}
	for {

		n, err := s.Reader.Read(s.buf[s.rend:cap(s.buf)])
		s.rend += n
		if err != nil {
			return s.buf[0:s.rend], err
		}
		if s.rend >= i {
			return s.buf[0:s.rend], nil
		}
	}
}

// Read will first return the buffered data, then read.
// For SNI routing we don't actually need this - in is a TcpConn and
// we'll use in.ReadFrom to take advantage of splice.
func (s *BufferReader) Read(d []byte) (int, error) {
	if s.rend > 0 {
		bn := copy(d, s.buf[s.roff:s.rend])
		s.roff += bn
		if s.roff == s.rend {
			s.rend = 0
		}
		return bn, nil
	}
	return s.Reader.Read(d)
}

func (s *BufferReader) Close() error {
	if s.buf != nil {
		bufferPoolCopy.Put(s.buf)
		s.buf = nil
	}
	if c, ok := s.Reader.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

