package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

// procKillGrace bounds how long Wait() blocks on a tool's output pipes AFTER the
// context is cancelled and the process group has been signalled. If a stray
// descendant still holds a pipe open past this, the exec package force-closes
// the pipes so Wait() returns instead of hanging.
const procKillGrace = 10 * time.Second

// hardenProc makes a subprocess killable as a whole PROCESS GROUP and bounds how
// long Wait blocks on its output pipes. Without this, exec.CommandContext kills
// only the tool's OWN pid on context cancellation (e.g. an operator skipping the
// network brute phase) — worker children the tool spawned (hydra's per-target
// workers, feroxbuster/dirsearch threads) survive and keep the stdout/stderr
// pipes open, so the pipe-reader goroutines never see EOF and Wait() blocks
// forever. That is the "skip network brute → scan stalls with no output" bug.
// Setpgid puts the tool in its own group; Cancel SIGKILLs the whole group; and
// WaitDelay force-closes the pipes if any descendant still lingers.
func hardenProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid signals the ENTIRE process group (see Setpgid above).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = procKillGrace
}

type Executor struct {
	cfg         *config.Config
	logger      *logger.Logger
	semaphore   chan struct{}
	mu          sync.Mutex
	activeProcs map[string]*exec.Cmd
}

func NewExecutor(cfg *config.Config, log *logger.Logger) *Executor {
	return &Executor{
		cfg:         cfg,
		logger:      log,
		semaphore:   make(chan struct{}, cfg.Limits.MaxToolExecutions),
		activeProcs: make(map[string]*exec.Cmd),
	}
}

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

type LineCallback func(line string)

func (e *Executor) RunWithCallback(ctx context.Context, taskID string, callback LineCallback, name string, args ...string) error {
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"), "PATH="+e.extendedPath())
	hardenProc(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	e.mu.Lock()
	e.activeProcs[taskID] = cmd
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.activeProcs, taskID)
		e.mu.Unlock()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" && callback != nil {
				e.safeCallback(name, callback, line)
			}
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			e.logger.Debug("Tool stderr", "tool", name, "line", scanner.Text())
		}
	}()

	wg.Wait()
	return cmd.Wait()
}

// safeCallback runs a per-line callback with panic recovery. A callback panics
// in this reader goroutine — not under the scheduler's recover — so without this
// a single malformed tool line could crash the whole process.
func (e *Executor) safeCallback(tool string, cb LineCallback, line string) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("Recovered from tool callback panic", "tool", tool, "panic", r)
		}
	}()
	cb(line)
}

func (e *Executor) Run(ctx context.Context, name string, args ...string) (*ExecResult, error) {
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	start := time.Now()
	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"), "PATH="+e.extendedPath())
	hardenProc(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("run %s: %w", name, err)
		}
	}

	return result, nil
}

func (e *Executor) KillTask(taskID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if cmd, ok := e.activeProcs[taskID]; ok {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

func (e *Executor) IsToolAvailable(name string) bool {
	path := e.findTool(name)
	if path == name {
		_, err := exec.LookPath(name)
		return err == nil
	}
	_, err := os.Stat(path)
	return err == nil
}

func (e *Executor) findTool(name string) string {
	localPath := filepath.Join(e.cfg.ToolsDir, name)
	if _, err := os.Stat(localPath); err == nil {
		return localPath
	}

	// Order matters: prefer the Go bin and /usr/local/bin (where the real
	// ProjectDiscovery tools live) BEFORE ~/.local/bin — a python package named
	// like a recon tool (e.g. the "httpx" HTTP library CLI) installs into
	// ~/.local/bin and would otherwise shadow the real tool and break probing.
		for _, dir := range []string{
		filepath.Join(os.Getenv("HOME"), "go", "bin"),
		"/usr/local/bin",
		"/opt/venv/bin",
		filepath.Join(os.Getenv("HOME"), ".local", "bin"), // pip/pipx installs (waymore/dirsearch/uro)
	} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	return name
}

func (e *Executor) extendedPath() string {
	existing := os.Getenv("PATH")
		extra := []string{
		e.cfg.ToolsDir,
		filepath.Join(os.Getenv("HOME"), "go", "bin"),
		"/opt/venv/bin",
		filepath.Join(os.Getenv("HOME"), ".local", "bin"), // pip/pipx installs (waymore)
		"/usr/local/go/bin",
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
	}
	return strings.Join(append(extra, existing), ":")
}

func (e *Executor) RunWithInputCallback(ctx context.Context, input io.Reader, taskID string, callback LineCallback, name string, args ...string) error {
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}

	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"), "PATH="+e.extendedPath())
	cmd.Stdin = input
	hardenProc(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	e.mu.Lock()
	e.activeProcs[taskID] = cmd
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.activeProcs, taskID)
		e.mu.Unlock()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			if line := sc.Text(); line != "" && callback != nil {
				e.safeCallback(name, callback, line)
			}
		}
	}()
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			e.logger.Debug("Tool stderr", "tool", name, "line", sc.Text())
		}
	}()
	wg.Wait()
	return cmd.Wait()
}

func (e *Executor) RunWithInput(ctx context.Context, input io.Reader, name string, args ...string) (*ExecResult, error) {
	select {
	case e.semaphore <- struct{}{}:
		defer func() { <-e.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	start := time.Now()
	toolPath := e.findTool(name)
	cmd := exec.CommandContext(ctx, toolPath, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"), "PATH="+e.extendedPath())
	cmd.Stdin = input
	hardenProc(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("run %s: %w", name, err)
		}
	}

	return result, nil
}
