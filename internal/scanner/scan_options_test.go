package scanner

import (
	"context"
	"testing"
)

func TestNoHostScopeBlocksEveryHost(t *testing.T) {
	ctx := WithNoHostScope(context.Background())
	if hostScopeSet(ctx) == nil {
		t.Fatal("explicit empty host scope must be non-nil")
	}
	for _, host := range []string{"play.google.com", "example.com", "anything.test"} {
		if hostInScope(ctx, host) {
			t.Errorf("expected %q out of scope", host)
		}
	}
	if got := filterURLsByHostScope(ctx, []string{"https://example.com/a"}); len(got) != 0 {
		t.Errorf("filterURLsByHostScope=%v, want empty", got)
	}
}

func TestHostScopeAcceptsURLsAndSubdomains(t *testing.T) {
	ctx := WithHostScope(context.Background(), []string{"https://App.Example.com/account", "*.example.org"})
	for _, host := range []string{"app.example.com", "api.app.example.com", "www.example.org"} {
		if !hostInScope(ctx, host) {
			t.Errorf("expected %q in scope", host)
		}
	}
	for _, host := range []string{"evil-example.com", "example.net"} {
		if hostInScope(ctx, host) {
			t.Errorf("expected %q out of scope", host)
		}
	}
}
