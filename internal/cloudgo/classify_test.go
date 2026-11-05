package cloudgo

import (
	"strings"
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassify_ProbeOK(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "probe", Message: "169.254.169.254/latest/meta-data/", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

func TestClassify_IdentityOK(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "identity", Message: "account=123 arn=... userid=...", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

func TestClassify_SimulateOK(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "simulate", Message: "action allowed", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

func TestClassify_DriverOK(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "driver", Message: "created access key", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

func TestClassify_ErrorSkipped(t *testing.T) {
	if got := ClassifyCloudData(proto.CloudData{
		Stage: "identity", Message: "sts error", OK: false,
	}); len(got) != 0 {
		t.Fatalf("OK=false should skip, got %+v", got)
	}
}

func TestClassify_DoneSkipped(t *testing.T) {
	if got := ClassifyCloudData(proto.CloudData{
		Stage: "done", OK: true, Done: true,
	}); len(got) != 0 {
		t.Fatalf("done should skip, got %+v", got)
	}
}

func TestClassify_UnknownStageSkips(t *testing.T) {
	if got := ClassifyCloudData(proto.CloudData{
		Stage: "nonsense", OK: true,
	}); len(got) != 0 {
		t.Fatalf("unknown stage should skip, got %+v", got)
	}
}

func TestClassify_ProbeAKIA(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "probe", OK: true,
		Message: "AWS credentials captured",
		Detail:  "{\"AccessKeyId\":\"AKIA1234567890ABCDEF\",\"SecretAccessKey\":\"...\"}",
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
	if !strings.Contains(got[0].Name, "AWS credentials") {
		t.Fatalf("name should name the credential type: %q", got[0].Name)
	}
}

func TestClassify_ProbeGCPToken(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "probe", OK: true,
		Detail: "/computeMetadata/v1/instance/service-accounts/default/token -> access_token=ya29...",
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical GCP token, got %+v", got)
	}
	if !strings.Contains(got[0].Name, "GCP") {
		t.Fatalf("name should name GCP: %q", got[0].Name)
	}
}

func TestClassify_ProbeAMIInfoOnly(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "probe", OK: true,
		Detail: "ami-id\ninstance-id\nhostname",
	})
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatalf("want 1 info, got %+v", got)
	}
}

func TestClassify_ProbeExtractAWS(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "probe-extract", OK: true,
		Message: "AWS credentials captured",
		Detail:  "AKIA1234…wxyz",
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

func TestClassify_ChainIdentityProved(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "chain-identity", OK: true,
		Message: "credential proved: arn:aws:sts::123:assumed-role/foo/bar",
		Detail:  "123 / AROA...",
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

func TestClassify_ChainIdentityRejected(t *testing.T) {
	if got := ClassifyCloudData(proto.CloudData{
		Stage: "chain-identity", OK: true,
		Message: "credential rejected: sts 403",
	}); len(got) != 0 {
		t.Fatalf("rejected credential should not fire a vuln, got %+v", got)
	}
}

func TestClassify_DriverCreateAccessKey(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "driver", OK: true,
		Message: "create_access_key succeeded for bob",
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
	if !strings.Contains(got[0].Name, "persistence") {
		t.Fatalf("name should mention persistence: %q", got[0].Name)
	}
}

func TestClassify_DriverAttachPolicy(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "driver", OK: true,
		Message: "attach_user_policy succeeded",
	})
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if !strings.Contains(got[0].Name, "policy attached") {
		t.Fatalf("name should describe policy attach: %q", got[0].Name)
	}
}

func TestClassify_DriverAssumeRole(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "driver", OK: true,
		Message: "assume_role succeeded",
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
}
