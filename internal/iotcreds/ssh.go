//go:build iotcreds_ssh

// SSH spray requires golang.org/x/crypto/ssh. It is behind a build tag so
// the rest of the package compiles without pulling the dependency.
//
// Enable with:
//
//	go get golang.org/x/crypto/ssh
//	go build -tags iotcreds_ssh ./...
//
// Without the tag, this file is excluded and spraySSH/SSOptions come from
// ssh_stub.go which returns "unsupported" for the ssh protocol.
package iotcreds

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSOptions controls an SSH spray.
type SSOptions struct {
	Host      string
	Port      int
	Timeout   time.Duration
	StopFirst bool
}

// spraySSH tries every credential against the SSH endpoint with password
// auth. It disables host key verification (irrelevant for a spray) and
// uses a short per-attempt timeout.
func spraySSH(ctx context.Context, opts SSOptions, onAttempt func(i int, c Cred, ok bool)) ([]Hit, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("iotcreds/ssh: host required")
	}
	if opts.Port == 0 {
		opts.Port = 22
	}
	if opts.Timeout == 0 {
		opts.Timeout = 6 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)

	cfg := &ssh.ClientConfig{
		User:            "",
		Auth:            nil,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         opts.Timeout,
	}

	var hits []Hit
	for i, c := range BuiltinCreds {
		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}
		cfg.User = c.User
		cfg.Auth = []ssh.AuthMethod{ssh.Password(c.Pass)}

		d := net.Dialer{Timeout: opts.Timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			if onAttempt != nil {
				onAttempt(i, c, false)
			}
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

		sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		ok := err == nil
		if ok {
			cli := ssh.NewClient(sshConn, chans, reqs)
			cli.Close()
		}
		conn.Close()

		if onAttempt != nil {
			onAttempt(i, c, ok)
		}
		if ok {
			hits = append(hits, Hit{
				Host: opts.Host, Port: opts.Port, Protocol: "ssh",
				Vendor: c.Vendor, User: c.User, Pass: c.Pass,
			})
			if opts.StopFirst {
				return hits, nil
			}
		}
	}
	return hits, nil
}
