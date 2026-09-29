package cloudgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS SigV4 in pure stdlib. Used to call STS and IAM from the agent when it
// holds a set of creds harvested from IMDS or supplied by the operator.
type AWSKey struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func sigV4(key AWSKey, method, host, path string, query url.Values,
	headers map[string]string, payload []byte) string {
	region := key.Region
	if region == "" {
		region = "us-east-1"
	}

	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qparts []string
	for _, k := range keys {
		qparts = append(qparts, url.QueryEscape(k)+"="+url.QueryEscape(query.Get(k)))
	}
	canonicalQuery := strings.Join(qparts, "&")

	hkeys := make([]string, 0, len(headers))
	for k := range headers {
		hkeys = append(hkeys, strings.ToLower(k))
	}
	sort.Strings(hkeys)
	var hlines []string
	for _, k := range hkeys {
		hlines = append(hlines, k+":"+strings.TrimSpace(headers[http.CanonicalHeaderKey(k)])+"\n")
	}
	canonicalHeaders := strings.Join(hlines, "")
	signedHeaders := strings.Join(hkeys, ";")

	payloadHash := sha256Hex(string(payload))
	canonicalRequest := strings.Join([]string{
		method,
		path,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	amzDate := headers["X-Amz-Date"]
	dateStamp := amzDate[:8]

	service := "sts"
	if strings.Contains(host, ".iam.") || strings.HasPrefix(host, "iam.") {
		service = "iam"
	}
	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+key.SecretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	return "AWS4-HMAC-SHA256 Credential=" + key.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func awsCall(key AWSKey, host, method, path string, query url.Values, body []byte) (int, []byte, error) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")

	headers := map[string]string{
		"Host":       host,
		"X-Amz-Date": amzDate,
	}
	if key.SessionToken != "" {
		headers["X-Amz-Security-Token"] = key.SessionToken
	}
	if len(body) > 0 {
		headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
	}

	auth := sigV4(key, method, host, path, query, headers, body)
	headers["Authorization"] = auth

	urlStr := "https://" + host + path
	if len(query) > 0 {
		urlStr += "?" + query.Encode()
	}
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, urlStr, rdr)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out, nil
}

// CallerIdentity from sts:GetCallerIdentity
type CallerIdentity struct {
	Account string
	Arn     string
	UserID  string
}

type stsIdentityResp struct {
	XMLName xml.Name `xml:"GetCallerIdentityResponse"`
	Result  struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
}

func GetCallerIdentity(key AWSKey) (CallerIdentity, error) {
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	code, respBody, err := awsCall(key, "sts.amazonaws.com", http.MethodPost, "/", nil, body)
	if err != nil {
		return CallerIdentity{}, fmt.Errorf("cloudgo: sts: %w", err)
	}
	if code != 200 {
		return CallerIdentity{}, fmt.Errorf("cloudgo: sts %d: %s", code, string(respBody))
	}
	var r stsIdentityResp
	if err := xml.Unmarshal(respBody, &r); err != nil {
		return CallerIdentity{}, fmt.Errorf("cloudgo: parse sts: %w", err)
	}
	return CallerIdentity{Account: r.Result.Account, Arn: r.Result.Arn, UserID: r.Result.UserID}, nil
}

// IAMUser
type IAMUser struct {
	UserName   string
	Arn        string
	CreateDate string
}

// IAMRole
type IAMRole struct {
	RoleName string
	Arn      string
}

type listUsersResp struct {
	XMLName xml.Name `xml:"ListUsersResponse"`
	Result  struct {
		Users []struct {
			UserName   string `xml:"UserName"`
			Arn        string `xml:"Arn"`
			CreateDate string `xml:"CreateDate"`
		} `xml:"Users>member"`
	} `xml:"ListUsersResult"`
}

type listRolesResp struct {
	XMLName xml.Name `xml:"ListRolesResponse"`
	Result  struct {
		Roles []struct {
			RoleName string `xml:"RoleName"`
			Arn      string `xml:"Arn"`
		} `xml:"Roles>member"`
	} `xml:"ListRolesResult"`
}

func ListUsers(key AWSKey) ([]IAMUser, error) {
	body := []byte("Action=ListUsers&Version=2010-05-08")
	code, respBody, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, body)
	if err != nil {
		return nil, fmt.Errorf("cloudgo: iam list-users: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("cloudgo: iam list-users %d", code)
	}
	var r listUsersResp
	if err := xml.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("cloudgo: parse list-users: %w", err)
	}
	users := make([]IAMUser, 0, len(r.Result.Users))
	for _, u := range r.Result.Users {
		users = append(users, IAMUser{UserName: u.UserName, Arn: u.Arn, CreateDate: u.CreateDate})
	}
	return users, nil
}

func ListRoles(key AWSKey) ([]IAMRole, error) {
	body := []byte("Action=ListRoles&Version=2010-05-08")
	code, respBody, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, body)
	if err != nil {
		return nil, fmt.Errorf("cloudgo: iam list-roles: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("cloudgo: iam list-roles %d", code)
	}
	var r listRolesResp
	if err := xml.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("cloudgo: parse list-roles: %w", err)
	}
	roles := make([]IAMRole, 0, len(r.Result.Roles))
	for _, x := range r.Result.Roles {
		roles = append(roles, IAMRole{RoleName: x.RoleName, Arn: x.Arn})
	}
	return roles, nil
}

// SimulateActionResult
type SimulateActionResult struct {
	Action   string
	Decision string
}

type simulateResp struct {
	EvaluationResults []struct {
		EvalActionName string `json:"EvalActionName"`
		EvalDecision   string `json:"EvalDecision"`
	} `json:"EvaluationResults"`
}

func SimulatePrincipalPolicy(key AWSKey, policySourceArn string, actions []string) ([]SimulateActionResult, error) {
	vals := url.Values{}
	vals.Set("Action", "SimulatePrincipalPolicy")
	vals.Set("Version", "2010-05-08")
	vals.Set("PolicySourceArn", policySourceArn)
	for i, a := range actions {
		vals.Set(fmt.Sprintf("ActionNames.member.%d", i+1), a)
	}
	body := []byte(vals.Encode())
	code, respBody, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, body)
	if err != nil {
		return nil, fmt.Errorf("cloudgo: iam simulate: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("cloudgo: iam simulate %d", code)
	}
	var r simulateResp
	if err := json.Unmarshal(respBody, &r); err != nil {
		return nil, fmt.Errorf("cloudgo: parse simulate: %w", err)
	}
	out := make([]SimulateActionResult, 0, len(r.EvaluationResults))
	for _, e := range r.EvaluationResults {
		out = append(out, SimulateActionResult{Action: e.EvalActionName, Decision: e.EvalDecision})
	}
	return out, nil
}

// ProbeActions is the privesc-candidate list.
var ProbeActions = []string{
	"iam:CreateAccessKey", "iam:CreateUser", "iam:CreateLoginProfile",
	"iam:UpdateLoginProfile", "iam:AddUserToGroup", "iam:AttachUserPolicy",
	"iam:AttachRolePolicy", "iam:AttachGroupPolicy", "iam:PutUserPolicy",
	"iam:PutRolePolicy", "iam:PutGroupPolicy", "iam:PassRole",
	"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
	"iam:UpdateAssumeRolePolicy", "iam:CreateRole", "iam:CreateInstanceProfile",
	"iam:AddRoleToInstanceProfile", "iam:TagRole",
	"sts:AssumeRole", "sts:GetCallerIdentity", "sts:GetFederationToken",
	"ec2:*", "s3:*", "lambda:*", "dynamodb:*", "secretsmanager:*",
	"ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
	"kms:Decrypt", "kms:Encrypt", "kms:CreateGrant",
}
