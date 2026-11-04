package agentfw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sk666G/red-sky---arsenal/internal/cloudgo"
)

type cloudModule struct{}

func init() { Register(cloudModule{}) }

func (cloudModule) Name() string { return "cloud" }

// cloudArgs mirrors the JSON shape the core-side regCloudArgs produces.
// cloud has 20+ fields across 6 action families (probe/chain/identity/
// users/roles/simulate/driver), so positional args don't fit — the core
// sends one JSON blob as args[0].
type cloudArgs struct {
	Action    string `json:"action,omitempty"`
	Provider  string `json:"provider,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Secret    string `json:"secret,omitempty"`
	Token     string `json:"token,omitempty"`
	Region    string `json:"region,omitempty"`
	Arn       string `json:"arn,omitempty"`
	Driver    string `json:"driver,omitempty"`
	User      string `json:"user,omitempty"`
	Group     string `json:"group,omitempty"`
	PolicyArn string `json:"policy_arn,omitempty"`
	RoleArn   string `json:"role_arn,omitempty"`
}

func (cloudModule) Run(ctx context.Context, args []string) Result {
	if len(args) == 0 {
		return Result{Err: fmt.Errorf("cloud needs a JSON args blob as args[0]"), ExitCode: 2}
	}
	var a cloudArgs
	if err := json.Unmarshal([]byte(args[0]), &a); err != nil {
		return Result{Err: fmt.Errorf("cloud: decode args: %w", err), ExitCode: 2}
	}

	var b strings.Builder
	fail := func(stage, msg string, err error) Result {
		fmt.Fprintf(&b, "%s: %s\n", stage, msg)
		if err != nil {
			fmt.Fprintf(&b, "  error: %v\n", err)
		}
		return Result{Output: b.String(), Err: err, ExitCode: 1}
	}

	key := cloudgo.AWSKey{
		AccessKeyID:     a.KeyID,
		SecretAccessKey: a.Secret,
		SessionToken:    a.Token,
		Region:          a.Region,
	}

	switch a.Action {
	case "probe", "imds_probe":
		var results []cloudgo.ProbeResult
		switch a.Provider {
		case "aws":
			results = cloudgo.ProbeAWS(cloudgo.IMDSOptions{})
		case "gcp":
			results = cloudgo.ProbeGCP(cloudgo.IMDSOptions{})
		case "azure":
			results = cloudgo.ProbeAzure(cloudgo.IMDSOptions{})
		default:
			return Result{Err: fmt.Errorf("cloud probe: provider must be aws|gcp|azure"), ExitCode: 2}
		}
		fmt.Fprintf(&b, "cloud probe %s -> %d result(s)\n", a.Provider, len(results))
		for _, r := range results {
			det := r.Body
			if len(det) > 800 {
				det = det[:800]
			}
			if r.Error != "" {
				det = r.Error
			}
			fmt.Fprintf(&b, "  [%v] %s\n    %s\n", r.OK, r.URL, det)
		}

	case "chain":
		name, results := cloudgo.ProbeChain(cloudgo.IMDSOptions{})
		if name == "" {
			fmt.Fprintf(&b, "cloud chain: no cloud IMDS reachable\n")
		} else {
			fmt.Fprintf(&b, "cloud chain: live=%s -> %d result(s)\n", name, len(results))
			for _, r := range results {
				if r.OK {
					fmt.Fprintf(&b, "  %s\n", r.URL)
				}
			}
		}

	case "identity":
		id, err := cloudgo.GetCallerIdentity(key)
		if err != nil {
			return fail("identity", "sts error", err)
		}
		fmt.Fprintf(&b, "identity: account=%s arn=%s userid=%s\n", id.Account, id.Arn, id.UserID)

	case "users":
		users, err := cloudgo.ListUsers(key)
		if err != nil {
			return fail("iam", "list-users error", err)
		}
		fmt.Fprintf(&b, "iam users -> %d\n", len(users))
		for _, u := range users {
			fmt.Fprintf(&b, "  %s  %s\n", u.UserName, u.Arn)
		}

	case "roles":
		roles, err := cloudgo.ListRoles(key)
		if err != nil {
			return fail("iam", "list-roles error", err)
		}
		fmt.Fprintf(&b, "iam roles -> %d\n", len(roles))
		for _, r := range roles {
			fmt.Fprintf(&b, "  %s  %s\n", r.RoleName, r.Arn)
		}

	case "simulate":
		if a.Arn == "" {
			return Result{Err: fmt.Errorf("cloud simulate: arn required"), ExitCode: 2}
		}
		results, err := cloudgo.SimulatePrincipalPolicy(key, a.Arn, nil)
		if err != nil {
			return fail("simulate", "policy simulation error", err)
		}
		fmt.Fprintf(&b, "iam simulate %s -> %d action(s)\n", a.Arn, len(results))
		for _, r := range results {
			fmt.Fprintf(&b, "  [%s] %s\n", r.Decision, r.Action)
		}

	case "driver":
		if a.Driver == "" {
			return Result{Err: fmt.Errorf("cloud driver: driver name required"), ExitCode: 2}
		}
		out, err := cloudgo.ApplyDriver(key, a.Driver, cloudgo.DriverOptions{
			TargetUser:  a.User,
			TargetGroup: a.Group,
			PolicyARN:   a.PolicyArn,
			RoleARN:     a.RoleArn,
		})
		if err != nil {
			return fail("driver", a.Driver, err)
		}
		fmt.Fprintf(&b, "driver %s: %s\n", a.Driver, out)

	default:
		return Result{Err: fmt.Errorf("cloud: unknown action %q (probe|chain|identity|users|roles|simulate|driver)", a.Action), ExitCode: 2}
	}

	return Result{Output: b.String(), ExitCode: 0}
}
