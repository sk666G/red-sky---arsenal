package cloudgo

import (
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassify_ProbeOK(t *testing.T) {
	got := ClassifyCloudData(proto.CloudData{
		Stage: "probe", Message: "169.254.169.254/latest/meta-data/", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "critical" {
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
