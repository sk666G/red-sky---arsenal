# Red Sky Framework — Architecture

Status: draft
Target: v3.0
Baseline: v2.0.0 (e137b61)
Goal: turn Red Sky from a Python toolkit into a real offensive framework

## 1. Goals

- One operator binary: redsky (Go)
- One agent binary per OS: redsky-agent (Go, cross-compiled)
- 66 existing Python modules keep working as plugins
- C2 is the spine, not a module
- Operator UI: TUI first, web later
- Extensible plugin ABI
- Signed releases, one archive per OS

## 2. Non-goals

- Not a SOAR platform
- Not a detection platform
- Not a cloud service
- Not a web app scanner
- Not a mobile RE suite

## 3. Component map

redsky-core (Go) <-> redsky-agent (Go) over mTLS / HTTPS / DNS / WireGuard / SMB
redsky-core spawns Python plugins over JSON-RPC stdin/stdout

## 4. Transport layer

mTLS over TCP (default). HTTPS, DNS, WireGuard, SMB named pipe as fallbacks.

## 5. Agent protocol

JSON default, CBOR optional. AES-256-GCM per session (X25519 ECDH). zstd compression.
Framing: magic RS, version, flags, length, payload.

## 6. Session model

Engagement -> agents -> sessions -> tasks -> loot -> tunnels.
Persisted under ~/.redsky/engagements/<name>/ (sqlite + flat files).

## 7. Plugin ABI

Each Python module gets a wrapper that reads JSON from stdin, calls run_cli
with translated args, writes JSON result to stdout.

## 8. Operator UI

TUI in Go (bubbletea + lipgloss). Web UI in v3.1.

## 9. Build and release

Matrix: linux/darwin/windows/freebsd x amd64/arm64.
Artifacts: redsky-core, redsky-agent, docs, default config.

## 10. Evasion strategy

Agent: direct syscalls, ETW patch, AMSI, sleep mask, malleable profiles.

## 11. Framework security

Operator auth via local SSH key. Sessions isolated per engagement.

## 12. Testing

Unit tests per Go package. Integration tests against lab/.

## 13. Roadmap

Phase 0: architecture doc (this file)
Phase 1: Go core + Go agent + one command end-to-end
Phase 2: Python plugin bridge
Phase 3: TUI
Phase 4: port perf-critical modules to Go
Phase 5: evasion + loaders + plugin SDK
Phase 6: AI-native tasking
