package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestAbortXSSBrowserSessionIsOwnerScopedAndKillsProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group assertion uses the Unix sleep utility")
	}
	cmd := exec.CommandContext(context.Background(), "sleep", "30") // #nosec G204 -- fixed test command and arguments
	configureXSSBrowserProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	profile := filepath.Join(t.TempDir(), "reconner-xss-test")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	allocatorCancelled := make(chan struct{})
	b := &browserXSSConfirmer{
		dataDir:     profile,
		process:     cmd.Process,
		allocCancel: func() { close(allocatorCancelled) },
		navGate:     gate,
		activeOwner: "task-a",
		activeLease: 1,
	}

	if b.abortSession("task-b", 0) {
		t.Fatal("a different task must not abort the active browser")
	}
	if !b.abortSession("task-a", 0) {
		t.Fatal("active task did not abort its browser")
	}
	select {
	case <-allocatorCancelled:
	case <-time.After(time.Second):
		t.Fatal("allocator cancellation was not invoked")
	}
	waited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("browser process survived task abort")
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("browser profile still exists after abort: %v", err)
	}
	if b.navGate == gate {
		t.Fatal("abort must replace a gate potentially held by a stuck goroutine")
	}
}

func TestBrowserOperationContextFollowsPhaseCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(WithXSSBrowserOwner(context.Background(), "task-a"))
	gate := make(chan struct{}, 1)
	b := &browserXSSConfirmer{navGate: gate, activeOwner: "task-a", activeLease: 7}
	ctx, finish := b.operationContext(parent, context.Background(), time.Hour, 7)
	defer finish()
	cancelParent()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("phase cancellation did not cancel browser operation")
	}
	gateWasReplaced := func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.navGate != gate
	}
	deadline := time.Now().Add(time.Second)
	for !gateWasReplaced() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !gateWasReplaced() {
		t.Fatal("phase cancellation did not abort the browser session")
	}
}
