// Package main is the RED SKY browser panel. Reads the engagement DB
// through the same public API the TUI engagement pane and the
// -engagement-stats CLI use, and serves a single HTML page plus a JSON
// API. Local-only by default (127.0.0.1) — no auth layer, not meant to
// be exposed to a network.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/engagement"
)

type statsResponse struct {
	DBPath     string         `json:"db_path"`
	Hosts      int            `json:"hosts"`
	Vulns      int            `json:"vulns"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
	TopVulns   []vulnRow      `json:"top_vulns"`
}

type vulnRow struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
	Host     string `json:"host"`
	HostID   int64  `json:"host_id"`
}

func main() {
	engName := flag.String("engagement", "default", "engagement name")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	db, err := engagement.Open(*engName)
	if err != nil {
		log.Fatalf("engagement.Open: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex(db))
	mux.HandleFunc("/api/stats", handleStats(db))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("red-sky-panel: listening on %s (engagement=%s)", *addr, db.Path())
	log.Fatal(srv.ListenAndServe())
}

// collectStats is the aggregation the JSON API serves. Same shape as
// printEngagementStats in cmd/redsky-core/main.go, factored for reuse.
func collectStats(db *engagement.DB) (statsResponse, error) {
	out := statsResponse{
		DBPath:     db.Path(),
		BySeverity: map[string]int{},
	}
	hosts, err := db.Hosts()
	if err != nil {
		return out, fmt.Errorf("hosts: %w", err)
	}
	out.Hosts = len(hosts)
	for _, h := range hosts {
		vulns, err := db.Vulns(h.ID)
		if err != nil {
			return out, fmt.Errorf("vulns host %d: %w", h.ID, err)
		}
		for _, v := range vulns {
			sev := v.Severity
			if sev == "" {
				sev = "info"
			}
			out.BySeverity[sev]++
			out.Vulns++
			out.TopVulns = append(out.TopVulns, vulnRow{
				Name:     v.Name,
				Severity: sev,
				Evidence: v.Evidence,
				Host:     h.IP,
				HostID:   h.ID,
			})
		}
	}
	findings, err := db.Findings("")
	if err != nil {
		return out, fmt.Errorf("findings: %w", err)
	}
	out.Findings = len(findings)

	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(out.TopVulns, func(i, j int) bool {
		ri, ok := rank[out.TopVulns[i].Severity]
		if !ok {
			ri = 99
		}
		rj, ok := rank[out.TopVulns[j].Severity]
		if !ok {
			rj = 99
		}
		return ri < rj
	})
	if len(out.TopVulns) > 20 {
		out.TopVulns = out.TopVulns[:20]
	}
	return out, nil
}

func handleStats(db *engagement.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := collectStats(db)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(stats)
	}
}

func handleIndex(db *engagement.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := collectStats(db)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err != nil {
			http.Error(w, "error loading stats: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, pageTemplate,
			stats.DBPath,
			stats.Hosts, stats.Vulns, stats.Findings,
			stats.BySeverity["critical"], stats.BySeverity["high"],
			stats.BySeverity["medium"], stats.BySeverity["low"],
			renderRows(stats.TopVulns),
		)
	}
}

func renderRows(vulns []vulnRow) string {
	if len(vulns) == 0 {
		return `<tr><td colspan="4" class="empty">(no vulns yet)</td></tr>`
	}
	var b []byte
	for _, v := range vulns {
		b = append(b, fmt.Sprintf(
			`<tr><td><span class="sev sev-%s">%s</span></td><td>%s</td><td>%s</td><td class="ev">%s</td></tr>`,
			v.Severity, v.Severity, esc(v.Name), esc(v.Host), esc(v.Evidence))...)
	}
	return string(b)
}

func esc(s string) string {
	var b []byte
	for _, c := range s {
		switch c {
		case '<':
			b = append(b, []byte("&lt;")...)
		case '>':
			b = append(b, []byte("&gt;")...)
		case '&':
			b = append(b, []byte("&amp;")...)
		case '"':
			b = append(b, []byte("&quot;")...)
		default:
			b = append(b, []byte(string(c))...)
		}
	}
	return string(b)
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RED SKY — engagement</title>
<style>
:root { --crimson:#DC143C; --bone:#E6DCD2; --ash:#787878; --bg:#0a0000; --border:#5A0000; }
body { background:var(--bg); color:var(--bone); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; margin:0; padding:2rem; }
h1 { color:var(--crimson); font-weight:400; letter-spacing:0.1em; margin:0 0 0.25rem; }
.dbpath { color:var(--ash); font-size:0.85rem; margin-bottom:1.5rem; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem; }
.stat { border:1px solid var(--border); padding:0.75rem 1rem; }
.stat .n { font-size:1.75rem; color:var(--bone); }
.stat .l { color:var(--ash); font-size:0.8rem; text-transform:uppercase; letter-spacing:0.1em; }
.stat.critical .n { color:var(--crimson); }
.stat.high .n { color:#FF4500; }
.stat.medium .n { color:#DAA520; }
table { width:100%%; border-collapse:collapse; font-size:0.9rem; }
th { color:var(--crimson); text-align:left; padding:0.5rem; border-bottom:1px solid var(--border); font-weight:400; }
td { padding:0.5rem; border-bottom:1px solid #1a0000; vertical-align:top; }
.sev { padding:0.1rem 0.5rem; font-size:0.8rem; }
.sev-critical { color:var(--crimson); border:1px solid var(--crimson); }
.sev-high { color:#FF4500; border:1px solid #FF4500; }
.sev-medium { color:#DAA520; border:1px solid #DAA520; }
.sev-low { color:#50C850; border:1px solid #50C850; }
.sev-info { color:var(--ash); border:1px solid var(--border); }
.ev { color:var(--ash); font-size:0.85rem; max-width:32rem; word-break:break-all; }
.empty { color:var(--ash); font-style:italic; }
</style>
</head>
<body>
<h1>RED SKY</h1>
<div class="dbpath">%s</div>
<div class="grid">
<div class="stat"><div class="n">%d</div><div class="l">hosts</div></div>
<div class="stat"><div class="n">%d</div><div class="l">vulns</div></div>
<div class="stat"><div class="n">%d</div><div class="l">findings</div></div>
<div class="stat"><div class="n">%d/%d/%d/%d</div><div class="l">C/H/M/L</div></div>
</div>
<table>
<thead><tr><th>severity</th><th>name</th><th>host</th><th>evidence</th></tr></thead>
<tbody>%s</tbody>
</table>
</body>
</html>`
