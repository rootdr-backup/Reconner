//go:build darwin

package scanner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureXSSBrowserProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		killXSSBrowserProcess(cmd.Process)
		return nil
	}
	cmd.WaitDelay = xssBrowserAbortWait + time.Second
}

func killXSSBrowserProcess(process *os.Process) {
	if process == nil || process.Pid <= 1 {
		return
	}
	_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
	_ = process.Kill()
}
