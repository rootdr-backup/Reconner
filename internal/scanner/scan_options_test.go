package scanner

import (
	"context"
	"testing"
)

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
