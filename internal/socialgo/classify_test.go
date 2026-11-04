package socialgo

import (
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassifySocial_Hit(t *testing.T) {
	got := ClassifySocial(proto.SocialData{
		Stage: "hit", OK: true,
		Message: "credential captured",
		Detail:  "username=admin password=hunter2",
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
	if got[0].Evidence != "username=admin password=hunter2" {
		t.Fatalf("evidence: %q", got[0].Evidence)
	}
}

func TestClassifySocial_Result(t *testing.T) {
	got := ClassifySocial(proto.SocialData{Stage: "result", OK: true, Message: "form submitted"})
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatalf("want 1 info, got %+v", got)
	}
}

func TestClassifySocial_Miss(t *testing.T) {
	if got := ClassifySocial(proto.SocialData{Stage: "miss"}); len(got) != 0 {
		t.Fatalf("miss should skip, got %+v", got)
	}
}

func TestClassifySocial_Done(t *testing.T) {
	if got := ClassifySocial(proto.SocialData{Stage: "hit", OK: true, Done: true}); len(got) != 0 {
		t.Fatalf("done should skip, got %+v", got)
	}
}
