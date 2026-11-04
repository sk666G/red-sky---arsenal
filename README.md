# RED SKY

Modular offensive framework. Recon, credential operations, phishing,
CCTV, application cracking, C2, and a per-campaign implant builder —
one operator console with CLI, browser panel, and TUI.

Authorized engagements only. See `docs/LEGAL.md`.

## Status

Engagement loop is closed end-to-end for eight module families. The
operator can dispatch a task from the core, watch the agent stream
results back over the tunnel, see them classified and written to the
engagement DB, and read them back through three surfaces: the TUI
engagement pane, the `-engagement-stats` CLI, and the `-report-from-db`
renderer.

Framework skeleton (dispatcher, session manager, wire protocol, sink
switch) is stable and tested. The module rack has twelve more lanes
open (`35 physical` through `50 ai_agent`); the eight below are the
ones that produce vulns in the engagement DB today.

## Closed loops

Each family below dispatches from the core, streams results from the
agent, classifies them into severity-scoped vulns, and writes them
against a real host in the engagement DB. `-report-from-db` reads the
same table the TUI reads.

| Family   | What it proves                                        | Severities                     |
| -------- | ----------------------------------------------------- | ------------------------------ |
| AD       | LDAP entry exposed, weak ACL, kerberoastable          | critical / high / medium / info |
| ICS      | unauthenticated PLC read/write, protocol exposure     | critical / high / medium       |
| Cloud    | IMDS reachable, STS identity resolved, privesc path   | critical / high / medium       |
| Web      | SSRF to IMDS, internal admin surface, HTTP reach      | critical / high / medium / info |
| Social   | credential or session captured on engagement page     | high / info                    |
| Drone    | MAVLink frames observed, capture attribution          | findings only (no vuln row)    |
| Bluetooth| remote GATT write, unencrypted read, writable char    | high / medium / info           |
| CCTV     | credentials captured, unauthenticated RTSP stream     | critical / high / medium       |
| Shellcode| payload artifact generated, not a vuln                | findings only                  |

**Findings vs vulns.** Families that only generate payloads (shellcode,
drone frames) or only render payloads (SSTI/XSS/XXE) emit findings
into the DB but do not write vulns. The classified-vuln row means
*this has been proven against a live target* — not *we sent a probe
and got a status code back*. Nothing is overstated.

## Operator surfaces

Four ways to read the engagement DB after a session:

**TUI (default)** — `redsky-core` with no flags opens the operator
console. The engagement pane sits between the events box and the prompt:
hosts count, vuln count, per-severity breakdown, and the top-10 vulns
sorted by severity. `[tab]` focuses the pane, `↑`/`↓` walks the rows,
`[enter]` opens the full vuln detail (name, severity, host, evidence
verbatim), `[esc]` returns, `[r]` refreshes.

**CLI summary** — `redsky-core -engagement-stats` prints hosts count,
vulns count, per-severity breakdown, findings count, and the top-10
vulns, then exits. Fast check without opening the TUI. Uses only the
public `engagement.DB` API — no SQL.

**Report renderer** — `redsky-core -report-from-db -report-title "..."
-report-out <path>` renders a full markdown report from the engagement
DB, core-side, no agent needed. Same table the TUI reads.

**Browser panel** — `redsky-panel -addr 127.0.0.1:8080` starts a small
HTTP server that reads the same DB. `GET /` serves a server-rendered
HTML page: hosts/vulns/findings counts, per-severity color coding, and
the top-20 vulns sorted by severity. `GET /api/stats` serves the same
data as JSON for scripting. Local-only by default, no auth layer —
binding to a network interface is a deliberate operator decision.

Four reader surfaces, one table. Every one above reads the same rows
the sink cases write. None of them write.

## Modules

See `ARMORY.md` for the full catalog.

## License

MIT — see `LICENSE`.
