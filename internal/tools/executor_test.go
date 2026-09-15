package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/pkg/logger"
)

func TestExecutorSparseConfigDoesNotDeadlock(t *testing.T) {
	t.Parallel()
	exec := NewExecutor(&config.Config{}, logger.New("error"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := exec.Run(ctx, "sh", "-c", "printf ready")
	if err != nil {
		t.Fatalf("sparse-config executor failed: %v", err)
	}
	if result.Stdout != "ready" {
		t.Fatalf("stdout = %q, want ready", result.Stdout)
	}
}

func TestExecutorRejectsUntrustedExecutableNames(t *testing.T) {
	exec := NewExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	for _, name := range []string{"", ".", "..", "../sh", "/bin/sh", `..\sh`, "sh;touch", "sh name", "🔥"} {
		t.Run(name, func(t *testing.T) {
			if exec.IsToolAvailable(name) {
				t.Fatalf("unsafe tool %q reported available", name)
			}
			if _, err := exec.Run(context.Background(), name); err == nil {
				t.Fatalf("Run accepted unsafe tool %q", name)
			}
			if err := exec.RunWithCallback(context.Background(), "task", nil, name); err == nil {
				t.Fatalf("RunWithCallback accepted unsafe tool %q", name)
			}
			if _, err := exec.RunWithInput(context.Background(), strings.NewReader("input"), name); err == nil {
				t.Fatalf("RunWithInput accepted unsafe tool %q", name)
			}
			if err := exec.RunWithInputCallback(context.Background(), strings.NewReader("input"), "task", nil, name); err == nil {
				t.Fatalf("RunWithInputCallback accepted unsafe tool %q", name)
			}
		})
	}
}

func TestToolFreeExecutorDisablesInputVariants(t *testing.T) {
	exec := NewToolFreeExecutor(&config.Config{ToolsDir: t.TempDir()}, logger.New("error"))
	if _, err := exec.RunWithInput(context.Background(), strings.NewReader("payload"), "sh"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RunWithInput error = %v, want disabled", err)
	}
	if err := exec.RunWithInputCallback(context.Background(), strings.NewReader("payload"), "task", nil, "sh"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("RunWithInputCallback error = %v, want disabled", err)
	}
}

func TestToolNameValidatorAllowsCuratedBareNames(t *testing.T) {
	for _, name := range []string{"httpx", "python3", "nuclei-templates", "tool_v2.1", "c++"} {
		if err := validateToolName(name); err != nil {
			t.Fatalf("validateToolName(%q): %v", name, err)
		}
	}
}
