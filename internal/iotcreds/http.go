package iotcreds

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPOptions controls an HTTP/HTTPS spray.
type HTTPOptions struct {
	Host      string        // target ip or hostname
	Port      int           // 80 or 443 usually
	UseTLS    bool          // https://
	Path      string        // default "/"
	Timeout   time.Duration // per-attempt; default 6s
	StopFirst bool          // stop after the first hit per host
}

// SprayHTTP tries every credential against the HTTP basic-auth endpoint.
// Returns every hit it finds. A 2xx/3xx response without a WWW-Authenticate
// header on the success path is treated as authenticated.
//
// onAttempt is called after every credential (index, cred, ok) — optional.
func SprayHTTP(ctx context.Context, opts HTTPOptions, onAttempt func(i int, c Cred, ok bool)) ([]Hit, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("iotcreds/http: host required")
	}
	if opts.Path == "" {
		opts.Path = "/"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 6 * time.Second
	}

	scheme := "http"
	if opts.UseTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, opts.Host, opts.Port, opts.Path)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&netDialer{Timeout: opts.Timeout}).DialContext,
	}
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 302 often means auth accepted — allow one hop
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var hits []Hit
	for i, c := range BuiltinCreds {
		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.SetBasicAuth(c.User, c.Pass)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		ok := false
		if err == nil {
			defer resp.Body.Close()
			// success = 2xx or 3xx without an auth challenge
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				hasChallenge := resp.Header.Get("WWW-Authenticate")
				if !strings.Contains(strings.ToLower(hasChallenge), "basic") {
					ok = true
				}
			}
		}
		if onAttempt != nil {
			onAttempt(i, c, ok)
		}
		if ok {
			hits = append(hits, Hit{
				Host: opts.Host, Port: opts.Port, Protocol: scheme,
				Vendor: c.Vendor, User: c.User, Pass: c.Pass,
			})
			if opts.StopFirst {
				return hits, nil
			}
		}
	}
	return hits, nil
}

// netDialer is a tiny wrapper so callers can pass just a timeout.
type netDialer struct{ Timeout time.Duration }

func (d *netDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: d.Timeout}).DialContext(ctx, network, addr)
}
