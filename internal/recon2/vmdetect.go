package recon2

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// VM / sandbox detection. Not for evasion — the operator wants to know if
// the agent landed in a lab before running the high-noise stages. The
// signals here are the cheap ones: filesystem markers, device names, CPU
// features, and system identifiers.
//
// A "detected" answer is a hint, not a guarantee. Real sandboxes hide most
// of these. A "not detected" answer is not a guarantee of a real target.

// VMResult is the outcome of one check.
type VMResult struct {
	Check    string `json:"check"`
	Signal   string `json:"signal"`
	Evidence string `json:"evidence,omitempty"`
	Positive bool   `json:"positive"`
}

// VMDetect runs the whole check suite and returns every positive signal.
func VMDetect() []VMResult {
	var out []VMResult
	add := func(check, signal, evidence string, positive bool) {
		out = append(out, VMResult{Check: check, Signal: signal, Evidence: evidence, Positive: positive})
	}

	// --- filesystem markers ---
	for _, f := range vmMarkerFiles() {
		if _, err := os.Stat(f); err == nil {
			add("file", f, "", true)
		}
	}

	// --- MAC prefix ---
	for _, ifc := range macAddresses() {
		if p := matchVMVendor(ifc); p != "" {
			add("mac", ifc, p, true)
		}
	}

	// --- DMI / SMBIOS on Linux ---
	if runtime.GOOS == "linux" {
		for _, p := range []string{
			"/sys/class/dmi/id/product_name",
			"/sys/class/dmi/id/sys_vendor",
			"/sys/class/dmi/id/board_vendor",
			"/sys/class/dmi/id/bios_vendor",
		} {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			val := strings.TrimSpace(string(b))
			if strings.Contains(strings.ToLower(val), "vmware") ||
				strings.Contains(strings.ToLower(val), "virtualbox") ||
				strings.Contains(strings.ToLower(val), "qemu") ||
				strings.Contains(strings.ToLower(val), "kvm") ||
				strings.Contains(strings.ToLower(val), "xen") ||
				strings.Contains(strings.ToLower(val), "hyper-v") ||
				strings.Contains(strings.ToLower(val), "parallels") ||
				strings.Contains(strings.ToLower(val), "bochs") {
				add("dmi", p, val, true)
			}
		}
	}

	// --- CPU hypervisor flag on Linux ---
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/cpuinfo")
		if err == nil {
			if strings.Contains(string(b), "hypervisor") {
				add("cpuinfo", "hypervisor flag", "", true)
			}
		}
	}

	// --- systemd-detect-virt (Linux) ---
	if runtime.GOOS == "linux" {
		if out, err := exec.Command("systemd-detect-virt", "-v").Output(); err == nil {
			v := strings.TrimSpace(string(out))
			if v != "" && v != "none" {
				add("systemd-detect-virt", v, "", true)
			}
		}
	}

	// --- uptime heuristic ---
	// Real hosts that just booted into the agent are unlikely; sandboxes
	// are almost always fresh. Uptime < 3 minutes → suspicious.
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/uptime"); err == nil {
			fields := strings.Fields(string(b))
			if len(fields) > 0 {
				if secs := parseFloatPrefix(fields[0]); secs > 0 && secs < 180 {
					add("uptime", fields[0]+"s", "system up < 3 min", true)
				}
			}
		}
	}

	// --- CPU count heuristic ---
	// Sandboxes typically have 1-2 vCPUs.
	if runtime.NumCPU() <= 2 {
		add("cpu", "ncpu<=2", "", true)
	}

	// --- hostname heuristic ---
	if h, err := os.Hostname(); err == nil {
		low := strings.ToLower(h)
		for _, pat := range []string{"sandbox", "malware", "sample", "cuckoo", "vm-", "vbox", "kali-vm"} {
			if strings.Contains(low, pat) {
				add("hostname", h, "matched "+pat, true)
			}
		}
	}

	return out
}

// vmMarkerFiles is the list of common VM / sandbox file paths.
func vmMarkerFiles() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"/proc/scsi/scsi", // contains "QEMU" / "VMware" entries
			"/sys/module/vboxguest",
			"/sys/module/vboxsf",
			"/sys/module/vmw_balloon",
			"/sys/module/vmw_vmci",
			"/sys/module/hv_balloon",
			"/sys/module/xen_privcmd",
			"/usr/bin/VBoxControl",
			"/usr/bin/VBoxService",
			"/usr/bin/vmware-toolbox-cmd",
			"/etc/vmware-tools",
			"/etc/init.d/vboxadd",
			"/lib/systemd/system/vboxadd-service.service",
		}
	case "windows":
		return []string{
			`C:\Windows\System32\drivers\VBoxMouse.sys`,
			`C:\Windows\System32\drivers\vmhgfs.sys`,
			`C:\Windows\System32\drivers\vmmouse.sys`,
			`C:\Windows\System32\drivers\vmrawdsk.sys`,
			`C:\Program Files\VMware\VMware Tools`,
			`C:\Program Files\Oracle\VirtualBox Guest Additions`,
		}
	case "darwin":
		return []string{
			"/Library/Application Support/VMware Tools",
			"/Library/Application Support/VirtualBox Guest Additions",
		}
	}
	return nil
}

// macAddresses returns the hardware addresses of every interface.
func macAddresses() []string {
	var out []string
	ifaces, err := netInterfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if len(ifc.HardwareAddr) > 0 {
			out = append(out, strings.ToLower(ifc.HardwareAddr.String()))
		}
	}
	return out
}

// matchVMVendor returns the VM vendor name if the MAC OUI matches a known
// hypervisor range, else "".
func matchVMVendor(mac string) string {
	// take the first 8 chars (xx:xx:xx) as the OUI
	if len(mac) < 8 {
		return ""
	}
	oui := mac[:8]
	switch {
	case strings.HasPrefix(oui, "00:05:69"),
		strings.HasPrefix(oui, "00:0c:29"),
		strings.HasPrefix(oui, "00:1c:14"),
		strings.HasPrefix(oui, "00:50:56"):
		return "vmware"
	case strings.HasPrefix(oui, "08:00:27"),
		strings.HasPrefix(oui, "0a:00:27"):
		return "virtualbox"
	case strings.HasPrefix(oui, "00:15:5d"):
		return "hyper-v"
	case strings.HasPrefix(oui, "52:54:00"):
		return "qemu/kvm"
	case strings.HasPrefix(oui, "00:16:3e"):
		return "xen"
	}
	return ""
}

// parseFloatPrefix parses a leading floating-point number without pulling
// strconv.
func parseFloatPrefix(s string) float64 {
	var v float64
	var seenDot bool
	var frac float64
	var fracDiv float64 = 10
	for _, c := range s {
		if c >= '0' && c <= '9' {
			if seenDot {
				frac += float64(c-'0') / fracDiv
				fracDiv *= 10
			} else {
				v = v*10 + float64(c-'0')
			}
			continue
		}
		if c == '.' && !seenDot {
			seenDot = true
			continue
		}
		break
	}
	return v + frac
}

// netInterfaces is a thin wrapper so callers in this package have one
// import to change if we ever swap the interface backend.
func netInterfaces() ([]net.Interface, error) {
	return net.Interfaces()
}
