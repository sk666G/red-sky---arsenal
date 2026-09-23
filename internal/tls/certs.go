// Package tls generates and loads the engagement CA + server cert used by
// redsky-core, and provides the client-side pinning check used by redsky-agent.
//
// Design note: TLS here provides transport confidentiality only. Mutual
// authentication is provided by the ECDH + AES-256-GCM session layer above
// TLS. We deliberately do not require client certificates because agent certs
// would have to be provisioned per-agent, and ECDH already authenticates both
// sides with ephemeral keys.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EngagementPaths are the files on disk that hold an engagement's TLS material.
type EngagementPaths struct {
	Dir       string
	CAPEM     string
	CAKey     string
	ServerPEM string
	ServerKey string
}

// Paths returns the standard engagement paths for a given root dir and name.
func Paths(root, name string) EngagementPaths {
	dir := filepath.Join(root, "engagements", name)
	return EngagementPaths{
		Dir:       dir,
		CAPEM:     filepath.Join(dir, "ca.pem"),
		CAKey:     filepath.Join(dir, "ca.key"),
		ServerPEM: filepath.Join(dir, "server.pem"),
		ServerKey: filepath.Join(dir, "server.key"),
	}
}

// EnsureCA generates the CA + server cert if they don't exist.
func (p EngagementPaths) EnsureCA(hosts []string) error {
	if _, err := os.Stat(p.CAPEM); err == nil {
		return nil
	}
	if err := os.MkdirAll(p.Dir, 0700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Red Sky Engagement CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(p.CAPEM, "CERTIFICATE", caDER); err != nil {
		return err
	}
	caKeyDER, _ := x509.MarshalECPrivateKey(caKey)
	if err := writePEM(p.CAKey, "EC PRIVATE KEY", caKeyDER); err != nil {
		return err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ips := []net.IP{}
	dns := []string{}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "redsky-core"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	// Write the server cert file as leaf+CA so the client sees the full chain.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := os.WriteFile(p.ServerPEM, append(leafPEM, caPEM...), 0600); err != nil {
		return err
	}
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	if err := writePEM(p.ServerKey, "EC PRIVATE KEY", srvKeyDER); err != nil {
		return err
	}
	return nil
}

// ServerTLSConfig loads the server cert + CA for redsky-core.
// No client certificate is required — ECDH provides mutual auth.
func (p EngagementPaths) ServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(p.ServerPEM, p.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// CAFingerprint returns the SHA-256 fingerprint of the CA certificate in
// colon-delimited hex, for out-of-band pinning.
func (p EngagementPaths) CAFingerprint() (string, error) {
	pemBytes, err := os.ReadFile(p.CAPEM)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("tls: bad CA PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return colonHex(sum[:]), nil
}

// ClientTLSConfig builds a tls.Config that pins the CA by fingerprint.
// The agent expects the server to present [leaf, CA]; it hashes the last cert
// in the presented chain, which must equal the pinned CA fingerprint.
func ClientTLSConfig(caFingerprint string) (*tls.Config, error) {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tls: no certs presented")
			}
			// Trust the last cert in the chain as the CA.
			last := rawCerts[len(rawCerts)-1]
			sum := sha256.Sum256(last)
			got := colonHex(sum[:])
			if got != caFingerprint {
				return fmt.Errorf("tls: pin mismatch\n  want %s\n  got  %s", caFingerprint, got)
			}
			return nil
		},
	}, nil
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func colonHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexChars[v>>4], hexChars[v&0x0f])
	}
	return string(out)
}

// HexFingerprint returns the raw hex fingerprint without colons.
func HexFingerprint(b []byte) string {
	return hex.EncodeToString(b)
}
