package tls

import (
	"crypto/tls"
	"net"
)

// tlsListener wraps a net.Listener so every accepted conn is wrapped in TLS.
type tlsListener struct {
	inner net.Listener
	cfg   *tls.Config
}

func newTLSListener(inner net.Listener, cfg *tls.Config) net.Listener {
	return &tlsListener{inner: inner, cfg: cfg}
}

// NewTLSListener is the exported constructor.
func NewTLSListener(inner net.Listener, cfg *tls.Config) net.Listener {
	return newTLSListener(inner, cfg)
}

func (l *tlsListener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(c, l.cfg), nil
}

func (l *tlsListener) Close() error   { return l.inner.Close() }
func (l *tlsListener) Addr() net.Addr { return l.inner.Addr() }
