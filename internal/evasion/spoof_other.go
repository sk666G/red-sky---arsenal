//go:build !windows

package evasion

import "time"

// SpoofedSleep delegates to time.Sleep on non-Windows platforms. The
// stack-spoof technique is Windows-specific (PE + NtWaitForSingleObject
// + entersyscall/exitsyscall under the Go runtime). Non-Windows targets
// get the plain sleep.
func SpoofedSleep(d time.Duration) error {
	time.Sleep(d)
	return nil
}
