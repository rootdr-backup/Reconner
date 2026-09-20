//go:build !linux && !darwin

package scanner

import (
	"os"
	"os/exec"
	"time"
)

func configureXSSBrowserProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		killXSSBrowserProcess(cmd.Process)
		return nil
	}
	cmd.WaitDelay = xssBrowserAbortWait + time.Second
}

func killXSSBrowserProcess(process *os.Process) {
	if process != nil {
		_ = process.Kill()
	}
}
