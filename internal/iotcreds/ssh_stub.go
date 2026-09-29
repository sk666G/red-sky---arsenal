//go:build !iotcreds_ssh

package iotcreds

import (
	"context"
	"errors"
	"time"
)

// SSOptions controls an SSH spray. This is the stub — the real one is
// behind the `iotcreds_ssh` build tag and needs golang.org/x/crypto/ssh.
type SSOptions struct {
	Host      string
	Port      int
	Timeout   time.Duration
	StopFirst bool
}

func spraySSH(ctx context.Context, opts SSOptions, onAttempt func(i int, c Cred, ok bool)) ([]Hit, error) {
	return nil, errors.New("iotcreds: ssh spray not compiled — rebuild with -tags iotcreds_ssh after `go get golang.org/x/crypto/ssh`")
}
