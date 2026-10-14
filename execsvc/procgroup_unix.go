//go:build !windows

package execsvc

import (
	"os/exec"
	"syscall"
)

// setProcGroup puts the script child in its own process group so the whole tree —
// including anything it detaches with subprocess.Popen, `&`, or nohup — can be killed as
// a unit. Without this, exec.CommandContext's default cancellation kills only the direct
// process and such grandchildren outlive the call (보안 리뷰: 세션 종료 후에도 자식 프로세스
// 잔존). Mirrors norma's tool.setDetached.
func setProcGroup(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Setpgid = true
}

// killProcGroup SIGKILLs the child's entire process group, reaping any process it left
// running. Safe to call after the child has exited: the group id stays valid while any
// member is alive, and it is a no-op when nothing remains.
func killProcGroup(c *exec.Cmd) {
	if c == nil || c.Process == nil {
		return
	}
	_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
}
