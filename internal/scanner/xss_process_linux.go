//go:build linux

package scanner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Put Chromium and all renderer children in a dedicated process group. This
// preserves chromedp's Linux parent-death protection while also letting Skip
// terminate the complete browser tree rather than only the root process.
func configureXSSBrowserProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
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
