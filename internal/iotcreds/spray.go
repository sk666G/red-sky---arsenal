package iotcreds

import (
	"context"
	"fmt"
	"time"
)

// SprayOptions is the union of every protocol option set.
type SprayOptions struct {
	Host      string
	Port      int
	Protocol  string // "http" | "https" | "telnet" | "ssh"
	Path      string // http only
	Timeout   int    // seconds; 0 uses protocol default
	StopFirst bool
}

// Spray runs the credential table against opts.Host with the given protocol.
// onAttempt fires after every credential attempt with (index, cred, ok).
// Returns every hit. protocol is validated; unknown values return an error.
func Spray(ctx context.Context, opts SprayOptions, onAttempt func(i int, c Cred, ok bool)) ([]Hit, error) {
	switch opts.Protocol {
	case "http":
		return SprayHTTP(ctx, HTTPOptions{
			Host:      opts.Host,
			Port:      opts.Port,
			UseTLS:    false,
			Path:      opts.Path,
			Timeout:   secondsOr(opts.Timeout, 6),
			StopFirst: opts.StopFirst,
		}, onAttempt)
	case "https":
		return SprayHTTP(ctx, HTTPOptions{
			Host:      opts.Host,
			Port:      opts.Port,
			UseTLS:    true,
			Path:      opts.Path,
			Timeout:   secondsOr(opts.Timeout, 6),
			StopFirst: opts.StopFirst,
		}, onAttempt)
	case "telnet":
		return sprayTelnet(ctx, TelnetOptions{
			Host:      opts.Host,
			Port:      opts.Port,
			Timeout:   secondsOr(opts.Timeout, 6),
			StopFirst: opts.StopFirst,
		}, onAttempt)
	case "ssh":
		return spraySSH(ctx, SSOptions{
			Host:      opts.Host,
			Port:      opts.Port,
			Timeout:   secondsOr(opts.Timeout, 6),
			StopFirst: opts.StopFirst,
		}, onAttempt)
	default:
		return nil, fmt.Errorf("iotcreds/spray: unknown protocol %q (http|https|telnet|ssh)", opts.Protocol)
	}
}

func secondsOr(n int, def int) time.Duration {
	if n <= 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}
