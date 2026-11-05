package cloudgo

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeIMDS serves canned per-path responses from a local httptest
// server. The probe functions are told to use its URL via
// IMDSOptions.BaseURL so tests do not need a live cloud.
func fakeIMDS(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// IMDSv2 token PUT — accept any request to the token path.
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Header().Set("X-aws-ec2-metadata-token", "test-token")
			io.WriteString(w, "test-token")
			return
		}
		if body, ok := routes[r.URL.Path]; ok {
			io.WriteString(w, body)
			return
		}
		http.NotFound(w, r)
	}))
}

func TestProbeAWS_RealPaths(t *testing.T) {
	// awsPaths — serve the ones that matter with realistic bodies.
	// /latest/meta-data/ in real IMDS returns a listing that includes
	// "ami-id" and "instance-id" as newline-separated field names.
	srv := fakeIMDS(t, map[string]string{
		"/latest/meta-data/":                          "ami-id\nhostname\ninstance-id\nlocal-ipv4",
		"/latest/meta-data/iam/security-credentials/": "test-role",
	})
	defer srv.Close()

	got := ProbeAWS(IMDSOptions{Timeout: 2 * time.Second, BaseURL: srv.URL})
	if len(got) == 0 {
		t.Fatal("expected results")
	}
	var foundListing, foundRolePath bool
	for _, r := range got {
		if !r.OK {
			continue
		}
		if r.URL == srv.URL+"/latest/meta-data/" {
			foundListing = true
			if !strings.Contains(r.Body, "ami-id") {
				t.Fatalf("listing should contain ami-id: %q", r.Body)
			}
		}
		if strings.HasSuffix(r.URL, "/iam/security-credentials/") {
			foundRolePath = true
			if r.Body != "test-role" {
				t.Fatalf("role path should return test-role: %q", r.Body)
			}
		}
	}
	if !foundListing {
		t.Fatalf("metadata listing path should have been hit OK: %+v", got)
	}
	if !foundRolePath {
		t.Fatalf("security-credentials path should have been hit OK: %+v", got)
	}
}

func TestProbeGCP_RealPaths(t *testing.T) {
	srv := fakeIMDS(t, map[string]string{
		"/computeMetadata/v1/":                                        "instance/\nproject/\n",
		"/computeMetadata/v1/instance/service-accounts/":              "default/\n",
		"/computeMetadata/v1/instance/service-accounts/default/token": `{"access_token":"ya29.test","token_type":"Bearer","expires_in":3600}`,
	})
	defer srv.Close()

	got := ProbeGCP(IMDSOptions{Timeout: 2 * time.Second, BaseURL: srv.URL})
	var foundToken bool
	for _, r := range got {
		if r.OK && strings.Contains(r.URL, "service-accounts/default/token") {
			foundToken = true
			tok, err := ExtractGCPToken(r.Body)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if tok.AccessToken != "ya29.test" {
				t.Fatalf("token: %q", tok.AccessToken)
			}
		}
	}
	if !foundToken {
		t.Fatalf("token path not hit: %+v", got)
	}
}

func TestProbeAzure_RealPaths(t *testing.T) {
	srv := fakeIMDS(t, map[string]string{
		"/metadata/identity/oauth2/token": `{"access_token":"eyJ0eXAi...","expires_in":"3599"}`,
	})
	defer srv.Close()

	got := ProbeAzure(IMDSOptions{Timeout: 2 * time.Second, BaseURL: srv.URL})
	var hit bool
	for _, r := range got {
		if r.OK && strings.Contains(r.URL, "identity/oauth2/token") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("azure MSI path not hit: %+v", got)
	}
}

func TestExtractAWSCredentials_RealBody(t *testing.T) {
	body := `{
		"Code": "Success",
		"LastUpdated": "2024-01-01T00:00:00Z",
		"Type": "AWS-HMAC",
		"AccessKeyId": "ASIAEXAMPLEKEY1234",
		"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"Token": "session-token-value",
		"Expiration": "2024-01-01T06:00:00Z"
	}`
	c, err := ExtractAWSCredentials(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c.AccessKeyID != "ASIAEXAMPLEKEY1234" {
		t.Fatalf("AccessKeyId: %q", c.AccessKeyID)
	}
	if c.SecretAccessKey == "" {
		t.Fatal("SecretAccessKey empty")
	}
	if c.Token == "" {
		t.Fatal("Token empty")
	}
}

func TestExtractGCPToken_RealBody(t *testing.T) {
	body := `{"access_token":"ya29.c.EXAMPLE","expires_in":3599,"token_type":"Bearer"}`
	tok, err := ExtractGCPToken(body)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if tok.AccessToken != "ya29.c.EXAMPLE" {
		t.Fatalf("AccessToken: %q", tok.AccessToken)
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType: %q", tok.TokenType)
	}
	if tok.ExpiresIn != 3599 {
		t.Fatalf("ExpiresIn: %d", tok.ExpiresIn)
	}
}

func TestAWSCredentialsJSONRoundTrip(t *testing.T) {
	c := AWSCredentials{
		Code:            "Success",
		Type:            "AWS-HMAC",
		AccessKeyID:     "ASIA...",
		SecretAccessKey: "secret",
		Token:           "token",
		Expiration:      "2024-01-01T00:00:00Z",
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var parsed AWSCredentials
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.AccessKeyID != c.AccessKeyID {
		t.Fatalf("AccessKeyID round-trip: %q != %q", parsed.AccessKeyID, c.AccessKeyID)
	}
}
