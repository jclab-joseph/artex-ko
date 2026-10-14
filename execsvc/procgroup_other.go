//go:build windows

package execsvc

import "os/exec"

// setProcGroup is a no-op on platforms without POSIX process groups; killProcGroup falls
// back to killing the lone process.
func setProcGroup(c *exec.Cmd) {}

func killProcGroup(c *exec.Cmd) {
	if c != nil && c.Process != nil {
		_ = c.Process.Kill()
	}
}
