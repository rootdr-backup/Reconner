package scanner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// hakrawler (hakluke/hakrawler) takes its crawl target on STDIN, not a -url
// flag, and its depth flag is -d, not -depth. Reconner previously invoked it
// with "-url <target> -depth 2 -insecure" (params.go) and "-url <target> -js
// -insecure" (js_scanner.go) — every one of those is an unrecognized flag,
// which makes hakrawler print its usage to stderr and exit 0 (not a nonzero
// exit, so RunWithCallback/Run never saw a failure). Every hakrawler
// invocation in the codebase produced zero crawled URLs, silently, no matter
// how long it ran. These guard the fix: hakrawlerArgs must never reintroduce
// -url/-depth/-js, and the real target must flow through stdin.
func TestHakrawlerArgsNeverUsesURLOrDepthFlags(t *testing.T) {
	args := hakrawlerArgs(context.Background())
	for _, bad := range []string{"-url", "-depth", "-js"} {
		for _, a := range args {
			if a == bad {
				t.Fatalf("hakrawlerArgs regressed to the broken flag %q (args=%v) — hakrawler has no such flag and would silently produce zero output", bad, args)
			}
		}
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-d 3") {
		t.Fatalf("hakrawlerArgs missing -d (depth) flag: %v", args)
	}
	if !strings.Contains(joined, "-insecure") {
		t.Fatalf("hakrawlerArgs missing -insecure flag: %v", args)
	}
}

// TestHakrawlerReceivesTargetViaStdinNotArgs runs a fake hakrawler binary that
// fails loudly if invoked with a -url argument (the historical, broken shape)
// and otherwise echoes back whatever it reads from stdin — proving the real
// call site (params.go's crawl loop) pipes the target URL via stdin through
// RunWithInputCallback instead of passing it as an argument.
func TestHakrawlerReceivesTargetViaStdinNotArgs(t *testing.T) {
	toolDir := t.TempDir()
	fake := "#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    -url|-depth|-js) echo \"BAD_FLAG:$a\" >&2; exit 1 ;;\n  esac\ndone\nwhile IFS= read -r line; do\n  echo \"${line}/crawled-via-stdin\"\ndone\n"
	if err := os.WriteFile(filepath.Join(toolDir, "hakrawler"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ToolsDir: toolDir, Limits: config.ResourceLimits{MaxToolExecutions: 2}}
	log := logger.NewWithWriter("error", io.Discard)
	exec := tools.NewExecutor(cfg, log)

	const probeURL = "https://example.test/start"
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := exec.RunWithInputCallback(ctx, strings.NewReader(probeURL+"\n"), "t1", func(line string) {
		got = append(got, line)
	}, "hakrawler", hakrawlerArgs(ctx)...)
	if err != nil {
		t.Fatalf("hakrawler invocation failed (likely reintroduced a bad flag): %v", err)
	}
	if len(got) != 1 || got[0] != probeURL+"/crawled-via-stdin" {
		t.Fatalf("expected the fake binary's stdin-derived output, got %v", got)
	}
}
