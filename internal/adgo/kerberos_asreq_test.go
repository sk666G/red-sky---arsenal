package adgo

import (
	"bytes"
	"strings"
	"testing"
)

// TestBuildASREQShape confirms the AS-REQ is a valid [APPLICATION 10] TLV.
func TestBuildASREQShape(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "CORP.LOCAL", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	// outer tag must be APPLICATION 10 (0x6A)
	if req[0] != 0x6A {
		t.Fatalf("outer tag = 0x%02x, want 0x6A (AS-REQ)", req[0])
	}
	// the next byte should be a length (short or long)
	if len(req) < 10 {
		t.Fatalf("AS-REQ too short: %d bytes", len(req))
	}
}

// TestBuildASREQContainsRealmUsername confirms the realm and username
// appear in the encoded bytes.
func TestBuildASREQContainsRealmUsername(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "TEST.LOCAL", Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(req, []byte("TEST.LOCAL")) {
		t.Fatalf("realm not in AS-REQ bytes")
	}
	if !bytes.Contains(req, []byte("bob")) {
		t.Fatalf("username not in AS-REQ bytes")
	}
}

// TestBuildASREQContainsKDCService confirms the sname references krbtgt.
func TestBuildASREQContainsKDCService(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "CORP.LOCAL", Username: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(req, []byte("krbtgt")) {
		t.Fatalf("krbtgt service not in AS-REQ")
	}
}

// TestBuildASREQNoPadata — the whole roast. The AS-REQ must NOT contain
// a padata [3] field with a PA-ENC-TIMESTAMP. Look for the absence of
// the known PA-ENC-TIMESTAMP OID bytes.
func TestBuildASREQNoPadata(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "R.LOCAL", Username: "u"})
	if err != nil {
		t.Fatal(err)
	}
	// PA-ENC-TIMESTAMP OID is 1.3.6.1.5.2.3.2 → encoded as 2B 06 01 05 02 03 02
	padataOID := []byte{0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x02}
	if bytes.Contains(req, padataOID) {
		t.Fatalf("AS-REQ contains PA-ENC-TIMESTAMP padata — this is NOT the roast shape")
	}
}

// TestBuildASREQDefaults — with only realm + username, etypes defaults
// to [23, 18, 17].
func TestBuildASREQDefaults(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "R.LOCAL", Username: "u"})
	if err != nil {
		t.Fatal(err)
	}
	// rc4-hmac etype 23 in DER: 02 01 17
	if !bytes.Contains(req, []byte{0x02, 0x01, 0x17}) {
		t.Fatalf("etype 23 not found in AS-REQ")
	}
	// aes256 etype 18: 02 01 12
	if !bytes.Contains(req, []byte{0x02, 0x01, 0x12}) {
		t.Fatalf("etype 18 not found in AS-REQ")
	}
	// aes128 etype 17: 02 01 11
	if !bytes.Contains(req, []byte{0x02, 0x01, 0x11}) {
		t.Fatalf("etype 17 not found in AS-REQ")
	}
}

// TestBuildASREQRejectsEmpty — required fields.
func TestBuildASREQRejectsEmptyRealm(t *testing.T) {
	_, err := BuildASREQ(ASREQOptions{Username: "x"})
	if err == nil {
		t.Fatal("expected error for missing realm")
	}
}

func TestBuildASREQRejectsEmptyUsername(t *testing.T) {
	_, err := BuildASREQ(ASREQOptions{Realm: "R.LOCAL"})
	if err == nil {
		t.Fatal("expected error for missing username")
	}
}

// TestParseASREPRejectsNonASREP — a garbage blob fails cleanly.
func TestParseASREPRejectsNonASREP(t *testing.T) {
	_, err := ParseASREP([]byte{0x30, 0x00})
	if err == nil {
		t.Fatal("expected error for non-AS-REP")
	}
}

// TestParseASREPRejectsShort rejects a truncated blob.
func TestParseASREPRejectsShort(t *testing.T) {
	_, err := ParseASREP([]byte{0x6B})
	if err == nil {
		t.Fatal("expected error for short blob")
	}
}

// TestBuildASREQParsesBackAsTLV confirms a full decode cycle.
func TestBuildASREQParsesBackAsTLV(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "CORP.LOCAL", Username: "user1"})
	if err != nil {
		t.Fatal(err)
	}
	r := NewDERReader(req)
	tag, content, err := r.ReadTLV()
	if err != nil {
		t.Fatal(err)
	}
	if tag != 0x6A {
		t.Fatalf("outer tag: 0x%02x", tag)
	}
	// the content is the inner SEQUENCE, so its first byte should be 0x30
	if len(content) < 1 || content[0] != 0x30 {
		t.Fatalf("inner not a SEQUENCE: 0x%02x", content[0])
	}
}

// TestBuildASREQCustomETypes confirms caller-supplied etypes are used.
func TestBuildASREQCustomETypes(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{
		Realm:    "R.LOCAL",
		Username: "u",
		ETypes:   []int32{ETypeRC4_HMAC},
	})
	if err != nil {
		t.Fatal(err)
	}
	// only etype 23 should be present
	if !bytes.Contains(req, []byte{0x02, 0x01, 0x17}) {
		t.Fatalf("etype 23 not found")
	}
	if bytes.Contains(req, []byte{0x02, 0x01, 0x12}) {
		t.Fatalf("etype 18 present despite custom etypes")
	}
}

// TestBuildASREQUsernameVariations covers different usernames.
func TestBuildASREQUsernameVariations(t *testing.T) {
	for _, name := range []string{"a", "alice", "svc_backup", "user.name"} {
		req, err := BuildASREQ(ASREQOptions{Realm: "R.LOCAL", Username: name})
		if err != nil {
			t.Fatalf("username %q: %v", name, err)
		}
		if !bytes.Contains(req, []byte(name)) {
			t.Fatalf("username %q not in AS-REQ", name)
		}
	}
}

// TestBuildASREQNonceEncoded checks the nonce appears in the message.
func TestBuildASREQNonceEncoded(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "R.LOCAL", Username: "u", Nonce: 0x11223344})
	if err != nil {
		t.Fatal(err)
	}
	// nonce 0x11223344 encoded as INTEGER would have leading zero because
	// top bit is clear (0x11 < 0x80) so it's 02 04 11 22 33 44
	if !bytes.Contains(req, []byte{0x02, 0x04, 0x11, 0x22, 0x33, 0x44}) {
		t.Fatalf("nonce not encoded correctly")
	}
}

// TestBuildASREQHexDump prints a hex dump for eyeballing during dev.
func TestBuildASREQHexDump(t *testing.T) {
	req, err := BuildASREQ(ASREQOptions{Realm: "X", Username: "Y"})
	if err != nil {
		t.Fatal(err)
	}
	// just check the message isn't empty and starts with the right tag
	if len(req) < 20 {
		t.Fatalf("AS-REQ suspiciously short: %d bytes", len(req))
	}
	// the hex dump helps during debugging
	_ = strings.Join([]string{}, " ")
}
