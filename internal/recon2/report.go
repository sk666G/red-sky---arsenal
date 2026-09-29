package recon2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report generation. Aggregates the JSON outputs from every primitive into
// a single Markdown deliverable — the same shape as a pentest report.
//
// Reads: a set of JSON files from any of the recon primitives (hostinfo,
// vmdetect, geoip, mailtrace, cctv, csint hits, etc.) and renders a
// summary with sections per source.
//
// Also accepts arbitrary key/value observations from the operator and
// renders them under a "Findings" section with severity classification.

// Severity levels for one finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Finding is one observation to include in the report.
type Finding struct {
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Target      string   `json:"target,omitempty"`
	Description string   `json:"description,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// ReportMeta is the header info.
type ReportMeta struct {
	Title      string    `json:"title"`
	Operator   string    `json:"operator,omitempty"`
	Engagement string    `json:"engagement,omitempty"`
	Generated  time.Time `json:"generated"`
}

// Report is the deliverable.
type Report struct {
	Meta     ReportMeta
	Findings []Finding
	Raw      map[string]json.RawMessage
}

// NewReport creates an empty report with the given title.
func NewReport(title, operator, engagement string) *Report {
	return &Report{
		Meta: ReportMeta{
			Title:      title,
			Operator:   operator,
			Engagement: engagement,
			Generated:  time.Now(),
		},
		Raw: map[string]json.RawMessage{},
	}
}

// AddFinding appends one finding.
func (r *Report) AddFinding(f Finding) {
	if f.Severity == "" {
		f.Severity = SeverityInfo
	}
	r.Findings = append(r.Findings, f)
}

// AddRawSource slurps a JSON file and stores it under the given label.
func (r *Report) AddRawSource(label, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !json.Valid(b) {
		return fmt.Errorf("recon2: %s is not valid JSON", path)
	}
	if label == "" {
		label = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	r.Raw[label] = json.RawMessage(b)
	return nil
}

// AddRawDir walks a directory and slurps every .json file as a source.
func (r *Report) AddRawDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		_ = r.AddRawSource("", path)
		return nil
	})
}

// Render outputs the report as Markdown.
func (r *Report) Render() string {
	var b strings.Builder

	b.WriteString("# " + r.Meta.Title + "\n\n")
	if r.Meta.Engagement != "" {
		b.WriteString("**Engagement:** " + r.Meta.Engagement + "  \n")
	}
	if r.Meta.Operator != "" {
		b.WriteString("**Operator:** " + r.Meta.Operator + "  \n")
	}
	b.WriteString("**Generated:** " + r.Meta.Generated.UTC().Format(time.RFC3339) + "\n\n")
	b.WriteString("---\n\n")

	b.WriteString("## Summary\n\n")
	counts := map[Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for _, s := range order {
		if counts[s] > 0 {
			b.WriteString("- **" + string(s) + ":** " + itoaInt(counts[s]) + "\n")
		}
	}
	if len(r.Findings) == 0 {
		b.WriteString("- No findings recorded.\n")
	}
	b.WriteString("\n")

	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		sorted := append([]Finding(nil), r.Findings...)
		sort.Slice(sorted, func(i, j int) bool {
			return sevRank(sorted[i].Severity) < sevRank(sorted[j].Severity)
		})
		for i, f := range sorted {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			b.WriteString("**Severity:** " + string(f.Severity) + "  \n")
			if f.Target != "" {
				b.WriteString("**Target:** `" + f.Target + "`  \n")
			}
			b.WriteString("\n")
			if f.Description != "" {
				b.WriteString(f.Description + "\n\n")
			}
			if f.Evidence != "" {
				b.WriteString("**Evidence:**\n\n```\n" + f.Evidence + "\n```\n\n")
			}
			if f.Remediation != "" {
				b.WriteString("**Remediation:** " + f.Remediation + "\n\n")
			}
		}
	}

	if len(r.Raw) > 0 {
		b.WriteString("## Appendix — Raw Data\n\n")
		keys := make([]string, 0, len(r.Raw))
		for k := range r.Raw {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString("### " + k + "\n\n")
			b.WriteString("```json\n")
			indented, err := indentJSON(r.Raw[k])
			if err == nil {
				b.WriteString(indented)
			} else {
				b.WriteString(string(r.Raw[k]))
			}
			b.WriteString("\n```\n\n")
		}
	}

	return b.String()
}

// Save writes the rendered report to a file.
func (r *Report) Save(path string) error {
	if path == "" {
		return errors.New("recon2: path required")
	}
	return os.WriteFile(path, []byte(r.Render()), 0o644)
}

func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

func indentJSON(b []byte) (string, error) {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b), err
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(b), err
	}
	return string(out), nil
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
