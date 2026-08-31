package tools

import (
	"context"
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
