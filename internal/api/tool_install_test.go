package api

import (
	"strings"
	"testing"
)

func TestToolCatalogIsPinnedAndHasNoRetiredNetworkTools(t *testing.T) {
	for name, spec := range toolCatalog {
		switch spec.Method {
		case methodGo:
			parts := strings.Split(spec.Ref, "@")
			if len(parts) != 2 || parts[1] == "" || parts[1] == "latest" {
				t.Errorf("Go tool %q is not pinned to one version: %q", name, spec.Ref)
			}
		case methodPip:
			parts := strings.Split(spec.Ref, "==")
			if len(parts) != 2 || parts[1] == "" {
				t.Errorf("Python tool %q is not pinned to one version: %q", name, spec.Ref)
			}
		}
		if strings.Contains(spec.Ref, "@latest") {
			t.Errorf("tool %q uses a moving latest ref: %q", name, spec.Ref)
		}
	}
	for _, retired := range []string{"nmap", "naabu", "hydra", "uncover", "dalfox", "gowitness"} {
		if _, ok := toolCatalog[retired]; ok {
			t.Errorf("retired/unused tool %q is still installable", retired)
		}
	}
}
