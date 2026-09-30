package recon2

import (
	"strings"
	"testing"
)

// TestParseDigestChallengeBasic parses a simple challenge.
func TestParseDigestChallengeBasic(t *testing.T) {
	h := `Digest realm="IP Camera", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth"`
	ch, ok := ParseDigestChallenge(h)
	if !ok {
		t.Fatal("parse failed")
	}
	if ch.Realm != "IP Camera" {
		t.Fatalf("realm = %q", ch.Realm)
	}
	if ch.Nonce != "dcd98b7102dd2f0e8b11d0f600bfb0c093" {
		t.Fatalf("nonce = %q", ch.Nonce)
	}
	if ch.QOP != "auth" {
		t.Fatalf("qop = %q", ch.QOP)
	}
	if !strings.EqualFold(ch.Algorithm, "MD5") {
		t.Fatalf("algorithm default = %q", ch.Algorithm)
	}
}

// TestParseDigestChallengeNotDigest rejects a Basic header.
func TestParseDigestChallengeNotDigest(t *testing.T) {
	if _, ok := ParseDigestChallenge(`Basic realm="X"`); ok {
		t.Fatal("Basic should not parse as Digest")
	}
}

// TestParseDigestChallengeNoNonce rejects a challenge missing nonce.
func TestParseDigestChallengeNoNonce(t *testing.T) {
	if _, ok := ParseDigestChallenge(`Digest realm="X"`); ok {
		t.Fatal("missing nonce should fail")
	}
}

// TestDigestResponseRFCExample is the RFC 2617 worked example. This is
// the canonical test vector for HTTP Digest MD5.
//
// From RFC 2617 §3.5:
//
//	username: "Mufasa"
//	password: "Circle Of Life"
//	realm:    "testrealm@host.com"
//	nonce:    "dcd98b7102dd2f0e8b11d0f600bfb0c093"
//	uri:      "/dir/index.html"
//	qop:      "auth"
//	nc:       "00000001"
//	cnonce:   "0a4f113b"
//	method:   "GET"
//
// Expected response: "6629fae49393a05397450978507c4ef1"
func TestDigestResponseRFCExample(t *testing.T) {
	ch := DigestChallenge{
		Realm:     "testrealm@host.com",
		Nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		QOP:       "auth",
		Algorithm: "MD5",
	}
	got := DigestResponse("Mufasa", "Circle Of Life", "GET", "/dir/index.html", ch, "0a4f113b", "00000001")
	want := "6629fae49393a05397450978507c4ef1"
	if got != want {
		t.Fatalf("RFC example mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestDigestResponseNoQOP — the simpler form without qop.
//
// HA1 = MD5("user:realm:pass")
// HA2 = MD5("GET:/path")
// response = MD5(HA1:nonce:HA2)
func TestDigestResponseNoQOP(t *testing.T) {
	ch := DigestChallenge{
		Realm: "realm",
		Nonce: "nonce123",
	}
	got := DigestResponse("admin", "password", "GET", "/", ch, "", "")
	// manual computation to verify the algorithm
	// HA1 = MD5("admin:realm:password")
	// HA2 = MD5("GET:/")
	// response = MD5(HA1:nonce123:HA2)
	if len(got) != 32 {
		t.Fatalf("response not 32 hex chars: %q", got)
	}
	// deterministic — same input produces same output
	got2 := DigestResponse("admin", "password", "GET", "/", ch, "", "")
	if got != got2 {
		t.Fatalf("digest response non-deterministic")
	}
}

// TestBuildDigestAuthorizationShape verifies the header value shape.
func TestBuildDigestAuthorizationShape(t *testing.T) {
	ch := DigestChallenge{Realm: "cam", Nonce: "abc123", QOP: "auth", Algorithm: "MD5"}
	auth := BuildDigestAuthorization("admin", "admin", "DESCRIBE", "rtsp://cam/", ch, "deadbeef", "00000001")
	if !strings.HasPrefix(auth, "Digest ") {
		t.Fatalf("missing Digest prefix: %q", auth)
	}
	for _, want := range []string{
		`username="admin"`,
		`realm="cam"`,
		`nonce="abc123"`,
		`uri="rtsp://cam/"`,
		`qop=auth`,
		`nc=00000001`,
		`cnonce="deadbeef"`,
	} {
		if !strings.Contains(auth, want) {
			t.Fatalf("auth missing %q: %s", want, auth)
		}
	}
}

// TestBuildDigestAuthorizationNoQOP confirms qop fields are omitted when
// the server didn't ask for qop.
func TestBuildDigestAuthorizationNoQOP(t *testing.T) {
	ch := DigestChallenge{Realm: "cam", Nonce: "abc123"}
	auth := BuildDigestAuthorization("admin", "admin", "OPTIONS", "rtsp://cam/", ch, "", "")
	if strings.Contains(auth, "qop=") {
		t.Fatalf("qop present without challenge qop: %q", auth)
	}
	if !strings.Contains(auth, "response=") {
		t.Fatalf("no response in auth: %q", auth)
	}
}

// TestFakeCnonceShape confirms the cnonce helper.
func TestFakeCnonceShape(t *testing.T) {
	if FakeCnonce(0xDEADBEEF) != "deadbeef" {
		t.Fatalf("FakeCnonce = %q", FakeCnonce(0xDEADBEEF))
	}
}
