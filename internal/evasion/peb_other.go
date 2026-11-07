//go:build !windows

package evasion

// WipePEHeaders is a no-op on non-Windows platforms. The technique is
// Windows-specific (PE format, GetModuleHandle semantics, VirtualProtect).
// On other targets the agent either has a different anti-inspection
// primitive or relies on the crypto + sleepmask layers already shipped.
func WipePEHeaders() error {
	return nil
}
