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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Inspired from okteto code: https://raw.githubusercontent.com/okteto/remote/main/pkg/ssh/ssh.go
// Removed deps on logger, integrated with ugate.

// Handles PTY/noPTY shell sessions and sftp.

// gliderlabs: current version doesn't work with certs. config() method requires a PublicKeyHandler, which
// doesn't have a reference to the conn ( because gliderlabs decided to invent it's 'better' interface ).
// In general the interface and abstractions are too complex and not needed.

var (
	idleTimeout = 60 * time.Second

	// ErrEOF is the error when the terminal exits
	ErrEOF = errors.New("EOF")
)

func getExitStatusFromError(err error) int {
	if err == nil {
		return 0
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return 1
	}

	waitStatus, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		if exitErr.Success() {
			return 0
		}

		return 1
	}

	return waitStatus.ExitStatus()
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func handlePTY(cmd *exec.Cmd, s *session, ptyReq Pty, winCh <-chan Window) error {
	if len(ptyReq.Term) > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	}

	f, err := pty.Start(cmd)
	if err != nil {
		log.Println("failed to start pty session", err)
		return err
	}

	go func() {
		for win := range winCh {
			setWinsize(f, win.Width, win.Height)
		}
	}()

	go func() {
		io.Copy(f, s) // stdin
	}()

	waitCh := make(chan struct{})
	go func() {
		defer close(waitCh)
		io.Copy(s, f) // stdout
	}()

	if err := cmd.Wait(); err != nil {
		log.Println("pty command failed while waiting", err)
		return err
	}

	select {
	case <-waitCh:
		log.Println("stdout finished")
	case <-time.NewTicker(1 * time.Second).C:
		log.Println("stdout didn't finish after 1s")
	}

	return nil
}

func sendErrAndExit(s *session, err error) {
	msg := strings.TrimPrefix(err.Error(), "exec: ")
	if _, err := s.Stderr().Write([]byte(msg)); err != nil {
		log.Println("failed to write error back to session", err)
	}

	if err := s.Exit(getExitStatusFromError(err)); err != nil {
		log.Println(err, "pty session failed to exit")
	}
}

func handleNoTTY(cmd *exec.Cmd, s *session) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Println(err, "couldn't get StdoutPipe")
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Println(err, "couldn't get StderrPipe")
		return err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Println(err, "couldn't get StdinPipe")
		return err
	}

	if err = cmd.Start(); err != nil {
		log.Println(err, "couldn't start command '%s'", cmd.String())
		return err
	}

	go func() {
		defer stdin.Close()
		if _, err := io.Copy(stdin, s); err != nil {
			log.Println(err, "failed to write session to stdin.")
		}
	}()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(s, stdout); err != nil {
			log.Println(err, "failed to write stdout to session.")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(s.Stderr(), stderr); err != nil {
			log.Println(err, "failed to write stderr to session.")
		}
	}()

	wg.Wait()

	if err := cmd.Wait(); err != nil {
		log.Println(err, "command failed while waiting")
		return err
	}

	return nil
}

type Signal string

// Window represents the size of a PTY window.
type Window struct {
	Width  int
	Height int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	Term   string
	Window Window
	// HELP WANTED: terminal modes!
}

type session struct {
	sync.Mutex
	ssh.Channel
	conn *ssh.ServerConn

	//handler           Handler
	//subsystemHandlers map[string]SubsystemHandler
	srv *Server

	handled bool
	exited  bool
	pty     *Pty
	winch   chan Window
	env     []string
	//ptyCb             PtyCallback
	rawCmd    string
	subsystem string
	sigCh     chan<- Signal
	sigBuf    []Signal
	breakCh   chan<- bool
}

func (sess *session) Write(p []byte) (n int, err error) {
	if sess.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
		p = bytes.Replace(p, []byte{'\n'}, []byte{'\r', '\n'}, -1)
		p = bytes.Replace(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'}, -1)
		n, err = sess.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return sess.Channel.Write(p)
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, ssh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

func (sess *session) Pty() (Pty, <-chan Window, bool) {
	if sess.pty != nil {
		return *sess.pty, sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

const maxSigBufSize = 128

func (sess *session) handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			//// If there's a session policy callback, we need to confirm before
			//// accepting the session.
			//if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
			//	sess.rawCmd = ""
			//	req.Reply(false, nil)
			//	continue
			//}

			sess.handled = true
			req.Reply(true, nil)

			go func() {
				sess.srv.connectionHandler(sess)
				sess.Exit(0)
			}()
		case "subsystem":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			ssh.Unmarshal(req.Payload, &payload)
			sess.subsystem = payload.Value

			//// If there's a session policy callback, we need to confirm before
			//// accepting the session.
			//if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
			//	sess.rawCmd = ""
			//	req.Reply(false, nil)
			//	continue
			//}

			if "sftp" == payload.Value {
				sess.handled = true
				req.Reply(true, nil)

				go func() {
					sftpHandler(sess)
					sess.Exit(0)
				}()
			} else {
				req.Reply(false, nil)
				continue
			}
		case "env":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			ssh.Unmarshal(req.Payload, &kv)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			ssh.Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "pty-req":
			if sess.handled || sess.pty != nil {
				req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			//if sess.ptyCb != nil {
			//	ok := sess.ptyCb(sess.ctx, ptyReq)
			//	if !ok {
			//		req.Reply(false, nil)
			//		continue
			//	}
			//}
			sess.pty = &ptyReq
			sess.winch = make(chan Window, 1)
			sess.winch <- ptyReq.Window
			defer func() {
				// when reqs is closed
				close(sess.winch)
			}()
			req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				req.Reply(false, nil)
				continue
			}
			win, ok := parseWinchRequest(req.Payload)
			if ok {
				sess.pty.Window = win
				sess.winch <- win
			}
			req.Reply(ok, nil)
		//case agentRequestType:
		//	// TODO: option/callback to allow agent forwarding
		//	SetAgentRequested(sess.ctx)
		//	req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			req.Reply(ok, nil)
			sess.Unlock()
		default:
			// TODO: debug log
			req.Reply(false, nil)
		}
	}
}

func (srv *Server) connectionHandler(s *session) {
	defer func() {
		s.Close()
		log.Println("session closed")
	}()

	log.Printf("starting ssh session with command '%+v'", s.rawCmd)

	cmd := srv.buildCmd(s)

	//if ssh.AgentRequested(s) {
	//	log.Println("agent requested")
	//	l, err := ssh.NewAgentListener()
	//	if err != nil {
	//		log.Println("failed to start agent", err)
	//		return
	//	}
	//
	//	defer l.Close()
	//	go ssh.ForwardAgentConnections(l, s)
	//	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", "SSH_AUTH_SOCK", l.Addr().String()))
	//}

	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		log.Println("handling PTY session")
		if err := handlePTY(cmd, s, ptyReq, winCh); err != nil {
			sendErrAndExit(s, err)
			return
		}

		s.Exit(0)
		return
	}

	log.Println("handling non PTY session")
	if err := handleNoTTY(cmd, s); err != nil {
		sendErrAndExit(s, err)
		return
	}

	s.Exit(0)
}

func sftpHandler(sess *session) {
	debugStream := ioutil.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		log.Println("sftp client exited session.")
	} else if err != nil {
		log.Println("sftp server completed with error:", err)
	}
}

func (srv Server) buildCmd(s *session) *exec.Cmd {
	var cmd *exec.Cmd

	cmdArgs := strings.Split(s.rawCmd, " ")
	if srv.Shell == "" {
		if len(cmdArgs) == 1 {
			cmd = exec.Command(cmdArgs[0])
		} else {
			cmd = exec.Command(cmdArgs[0], cmdArgs[1:]...)
		}
	} else {
		if len(s.rawCmd) == 0 {
			cmd = exec.Command(srv.Shell)
		} else {
			args := []string{"-c", s.rawCmd}
			cmd = exec.Command(srv.Shell, args...)
		}
	}

	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, s.env...)

	//fmt.Println(cmd.String())
	return cmd
}

func parsePtyRequest(s []byte) (pty Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = Pty{
		Term: term,
		Window: Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseWinchRequest(s []byte) (win Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}
