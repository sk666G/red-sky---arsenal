package icsgo

import (
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassify_ModbusWrite(t *testing.T) {
	got := ClassifyIcsData(proto.IcsData{
		Protocol: "modbus", Host: "10.0.0.5", Stage: "write",
		Message: "wrote 100 to 40001", OK: true,
	})
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Severity != "critical" {
		t.Fatalf("severity: %q", got[0].Severity)
	}
	if got[0].Name == "" || got[0].Evidence == "" {
		t.Fatalf("empty name or evidence: %+v", got[0])
	}
}

func TestClassify_ModbusRead(t *testing.T) {
	got := ClassifyIcsData(proto.IcsData{
		Protocol: "modbus", Host: "10.0.0.5", Stage: "read", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

func TestClassify_S7Read(t *testing.T) {
	got := ClassifyIcsData(proto.IcsData{
		Protocol: "s7", Host: "10.0.0.9", Stage: "read", OK: true,
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

func TestClassify_ErrorSkipped(t *testing.T) {
	if got := ClassifyIcsData(proto.IcsData{
		Protocol: "modbus", Host: "10.0.0.5", Stage: "error",
		Message: "connection refused", OK: false,
	}); len(got) != 0 {
		t.Fatalf("error stage should skip, got %+v", got)
	}
}

func TestClassify_DoneSkipped(t *testing.T) {
	if got := ClassifyIcsData(proto.IcsData{
		Protocol: "modbus", Stage: "done", OK: true, Done: true,
	}); len(got) != 0 {
		t.Fatalf("done should skip, got %+v", got)
	}
}

func TestClassify_MissingProtocolSkips(t *testing.T) {
	if got := ClassifyIcsData(proto.IcsData{
		Stage: "read", OK: true,
	}); len(got) != 0 {
		t.Fatalf("missing protocol should skip, got %+v", got)
	}
}
