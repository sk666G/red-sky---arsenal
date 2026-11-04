// Package engagement is the sqlite-backed state store for one engagement.
//
// Every host, service, vuln, credential, and raw finding the modules
// produce lands here. Reports read from the DB instead of walking the
// filesystem — so the state survives restarts, survives a module crash,
// and can be queried by any tool that knows the schema.
//
// One DB file per engagement: ~/.redsky/engagements/<name>/engagement.db.
// Schema auto-migrates on Open. The driver is modernc.org/sqlite (pure
// Go, no CGo, cross-compiles clean, works air-gapped).
package engagement

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB is one engagement's state store.
type DB struct {
	path string
	sql  *sql.DB
}

// Host is a discovered target host.
type Host struct {
	ID        int64
	IP        string
	Hostname  string
	OS        string
	FirstSeen time.Time
	LastSeen  time.Time
	Tags      []string
}

// Service is a network service on a host.
type Service struct {
	ID       int64
	HostID   int64
	Port     int
	Protocol string
	Banner   string
	State    string
}

// Vuln is a discovered vulnerability.
type Vuln struct {
	ID        int64
	HostID    int64
	ServiceID int64
	Name      string
	Severity  string
	Evidence  string
}

// Cred is a captured credential.
type Cred struct {
	ID      int64
	HostID  int64
	Service string
	User    string
	Pass    string
	Source  string
}

// Finding is a raw module output attached to a host.
type Finding struct {
	ID     int64
	Module string
	HostID int64
	Kind   string
	Data   json.RawMessage
	TS     time.Time
}

// Open opens (or creates) the engagement DB and runs schema migrations.
// The engagement name maps to ~/.redsky/engagements/<name>/engagement.db.
func Open(engagementName string) (*DB, error) {
	if engagementName == "" {
		return nil, errors.New("engagement: empty name")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("engagement: home dir: %w", err)
	}
	dir := filepath.Join(home, ".redsky", "engagements", engagementName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("engagement: mkdir: %w", err)
	}
	path := filepath.Join(dir, "engagement.db")

	// DSN: busy_timeout handles concurrent writes without hammering the caller
	// with SQLITE_BUSY. WAL mode gives us read-while-write which matters when
	// the TUI queries while a module writes.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("engagement: open: %w", err)
	}
	// SQLite tolerates one writer; serialising at the pool prevents lock storms.
	sqlDB.SetMaxOpenConns(1)

	d := &DB{path: path, sql: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the DB handle.
func (d *DB) Close() error { return d.sql.Close() }

// Path returns the absolute path of the DB file — for `-h` and diagnostics.
func (d *DB) Path() string { return d.path }

func (d *DB) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL UNIQUE,
    hostname   TEXT,
    os         TEXT,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    tags       TEXT
);
CREATE TABLE IF NOT EXISTS services (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    protocol TEXT,
    banner   TEXT,
    state    TEXT,
    UNIQUE(host_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS vulns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_id INTEGER REFERENCES services(id) ON DELETE SET NULL,
    name       TEXT NOT NULL,
    severity   TEXT,
    evidence   TEXT
);
CREATE TABLE IF NOT EXISTS creds (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service  TEXT,
    user     TEXT,
    pass     TEXT,
    source   TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    module  TEXT NOT NULL,
    host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    kind    TEXT,
    data    TEXT NOT NULL,
    ts      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulns(host_id);
CREATE INDEX IF NOT EXISTS idx_creds_host ON creds(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
`
	_, err := d.sql.Exec(schema)
	if err != nil {
		return fmt.Errorf("engagement: migrate: %w", err)
	}
	return nil
}

// UpsertHost inserts a host or updates its mutable fields. Returns host ID.
// IP is the unique key; the same IP always returns the same ID.
func (d *DB) UpsertHost(h Host) (int64, error) {
	if h.IP == "" {
		return 0, errors.New("engagement: host with empty IP")
	}
	now := time.Now().Unix()
	if h.FirstSeen.IsZero() {
		h.FirstSeen = time.Now()
	}
	if h.LastSeen.IsZero() {
		h.LastSeen = time.Now()
	}
	tagsJSON, _ := json.Marshal(h.Tags)

	// SQLite has no native UPSERT-on-conflict in old versions; the
	// INSERT ... ON CONFLICT clause is standard since 3.24 (2018),
	// available in modernc.org/sqlite.
	res, err := d.sql.Exec(`
INSERT INTO hosts(ip, hostname, os, first_seen, last_seen, tags)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
    hostname  = COALESCE(NULLIF(excluded.hostname, ''), hosts.hostname),
    os        = COALESCE(NULLIF(excluded.os, ''), hosts.os),
    last_seen = excluded.last_seen,
    tags      = COALESCE(NULLIF(excluded.tags, '[]'), hosts.tags)`,
		h.IP, h.Hostname, h.OS, h.FirstSeen.Unix(), now, string(tagsJSON))
	if err != nil {
		return 0, fmt.Errorf("engagement: upsert host: %w", err)
	}
	id, _ := res.LastInsertId()
	if id == 0 {
		// ON CONFLICT path — LastInsertId is stale, query the row.
		if err := d.sql.QueryRow(`SELECT id FROM hosts WHERE ip = ?`, h.IP).Scan(&id); err != nil {
			return 0, fmt.Errorf("engagement: host id lookup: %w", err)
		}
	}
	return id, nil
}

// UpsertService inserts or updates a service keyed by (host_id, port, protocol).
func (d *DB) UpsertService(s Service) (int64, error) {
	if s.HostID == 0 {
		return 0, errors.New("engagement: service without host_id")
	}
	res, err := d.sql.Exec(`
INSERT INTO services(host_id, port, protocol, banner, state)
VALUES(?, ?, ?, ?, ?)
ON CONFLICT(host_id, port, protocol) DO UPDATE SET
    banner = COALESCE(NULLIF(excluded.banner, ''), services.banner),
    state  = COALESCE(NULLIF(excluded.state, ''), services.state)`,
		s.HostID, s.Port, s.Protocol, s.Banner, s.State)
	if err != nil {
		return 0, fmt.Errorf("engagement: upsert service: %w", err)
	}
	id, _ := res.LastInsertId()
	if id == 0 {
		if err := d.sql.QueryRow(`SELECT id FROM services WHERE host_id=? AND port=? AND protocol=?`,
			s.HostID, s.Port, s.Protocol).Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// AddVuln appends a vuln row.
func (d *DB) AddVuln(v Vuln) (int64, error) {
	if v.HostID == 0 || v.Name == "" {
		return 0, errors.New("engagement: vuln without host_id or name")
	}
	res, err := d.sql.Exec(`INSERT INTO vulns(host_id, service_id, name, severity, evidence) VALUES(?, ?, ?, ?, ?)`,
		v.HostID, nullableInt(v.ServiceID), v.Name, v.Severity, v.Evidence)
	if err != nil {
		return 0, fmt.Errorf("engagement: add vuln: %w", err)
	}
	return res.LastInsertId()
}

// AddCred appends a credential row.
func (d *DB) AddCred(c Cred) (int64, error) {
	if c.HostID == 0 || c.User == "" {
		return 0, errors.New("engagement: cred without host_id or user")
	}
	res, err := d.sql.Exec(`INSERT INTO creds(host_id, service, user, pass, source) VALUES(?, ?, ?, ?, ?)`,
		c.HostID, c.Service, c.User, c.Pass, c.Source)
	if err != nil {
		return 0, fmt.Errorf("engagement: add cred: %w", err)
	}
	return res.LastInsertId()
}

// AddFinding appends a raw module finding.
func (d *DB) AddFinding(f Finding) (int64, error) {
	if f.Module == "" {
		return 0, errors.New("engagement: finding without module")
	}
	if f.TS.IsZero() {
		f.TS = time.Now()
	}
	if len(f.Data) == 0 {
		f.Data = []byte("null")
	}
	res, err := d.sql.Exec(`INSERT INTO findings(module, host_id, kind, data, ts) VALUES(?, ?, ?, ?, ?)`,
		f.Module, nullableInt(f.HostID), f.Kind, string(f.Data), f.TS.Unix())
	if err != nil {
		return 0, fmt.Errorf("engagement: add finding: %w", err)
	}
	return res.LastInsertId()
}

// Hosts returns all hosts ordered by last_seen desc.
func (d *DB) Hosts() ([]Host, error) {
	rows, err := d.sql.Query(`SELECT id, ip, COALESCE(hostname,''), COALESCE(os,''), first_seen, last_seen, COALESCE(tags,'[]') FROM hosts ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var fs, ls int64
		var tags string
		if err := rows.Scan(&h.ID, &h.IP, &h.Hostname, &h.OS, &fs, &ls, &tags); err != nil {
			return nil, err
		}
		h.FirstSeen = time.Unix(fs, 0)
		h.LastSeen = time.Unix(ls, 0)
		_ = json.Unmarshal([]byte(tags), &h.Tags)
		out = append(out, h)
	}
	return out, rows.Err()
}

// Services returns services for a host.
func (d *DB) Services(hostID int64) ([]Service, error) {
	rows, err := d.sql.Query(`SELECT id, host_id, port, COALESCE(protocol,''), COALESCE(banner,''), COALESCE(state,'') FROM services WHERE host_id=? ORDER BY port`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var s Service
		if err := rows.Scan(&s.ID, &s.HostID, &s.Port, &s.Protocol, &s.Banner, &s.State); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Vulns returns vulns for a host.
func (d *DB) Vulns(hostID int64) ([]Vuln, error) {
	rows, err := d.sql.Query(`SELECT id, host_id, COALESCE(service_id,0), name, COALESCE(severity,''), COALESCE(evidence,'') FROM vulns WHERE host_id=?`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vuln
	for rows.Next() {
		var v Vuln
		if err := rows.Scan(&v.ID, &v.HostID, &v.ServiceID, &v.Name, &v.Severity, &v.Evidence); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Creds returns creds for a host.
func (d *DB) Creds(hostID int64) ([]Cred, error) {
	rows, err := d.sql.Query(`SELECT id, host_id, COALESCE(service,''), user, COALESCE(pass,''), COALESCE(source,'') FROM creds WHERE host_id=?`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cred
	for rows.Next() {
		var c Cred
		if err := rows.Scan(&c.ID, &c.HostID, &c.Service, &c.User, &c.Pass, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Findings returns findings for a module ("" for all).
func (d *DB) Findings(module string) ([]Finding, error) {
	q := `SELECT id, module, COALESCE(host_id,0), COALESCE(kind,''), data, ts FROM findings`
	args := []any{}
	if module != "" {
		q += ` WHERE module = ?`
		args = append(args, module)
	}
	q += ` ORDER BY ts DESC`
	rows, err := d.sql.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var ts int64
		var data string
		if err := rows.Scan(&f.ID, &f.Module, &f.HostID, &f.Kind, &data, &ts); err != nil {
			return nil, err
		}
		f.Data = json.RawMessage(data)
		f.TS = time.Unix(ts, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}

func nullableInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}
