package scheduler

import (
	"slices"
	"testing"

	"github.com/recon-platform/internal/config"
)

// The System → Scanning page replaces the historical hardcoded monitor watch
// set. Regressions here surface as silently wrong check coverage: unknown
// names must be skipped (a stale config must not poison a future upgrade),
// the snapshot module must land before the first refresh-capable module —
// but AFTER subdomain_enum, so newly-appearing names stay inside the diffed
// baseline — and an empty/invalid list must fall back to the built-in set.
func TestMonitorWatchModulesHonorsConfiguredSet(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{MonitorModules: []string{ModuleSubdomainEnum, "totally_bogus", ModuleCORS}}
	got := s.monitorWatchModules()
	// Unknown names are skipped (not rejected), user order is preserved, and a
	// set without a snapshot module needs no hoisting.
	want := []string{ModuleSubdomainEnum, ModuleCORS}
	if !slices.Equal(got, want) {
		t.Fatalf("configured set not honored: got %v want %v", got, want)
	}
}

func TestMonitorWatchModulesMonitorBeforeRefresh(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{MonitorModules: []string{ModuleHTTPProbe, ModuleMonitor, ModuleSubdomainEnum}}
	got := s.monitorWatchModules()
	want := []string{ModuleMonitor, ModuleHTTPProbe, ModuleSubdomainEnum}
	if !slices.Equal(got, want) {
		t.Fatalf("monitor not hoisted ahead of the refresh module: got %v want %v", got, want)
	}
}

func TestMonitorWatchModulesMonitorStaysAfterSubdomainEnum(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{MonitorModules: []string{ModuleSubdomainEnum, ModuleHTTPProbe, ModuleMonitor, ModuleCORS}}
	got := s.monitorWatchModules()
	// Monitor sits before http_probe (the first refresh-capable module) but is
	// NOT hoisted to the absolute front ahead of subdomain enumeration.
	want := []string{ModuleSubdomainEnum, ModuleMonitor, ModuleHTTPProbe, ModuleCORS}
	if !slices.Equal(got, want) {
		t.Fatalf("snapshot jumped ahead of subdomain_enum: got %v want %v", got, want)
	}
}

func TestMonitorWatchModulesEmptyConfigUsesBuiltInSet(t *testing.T) {
	s := newTestScheduler(t)
	got := s.monitorWatchModules()
	if !slices.Equal(got, DefaultMonitorWatchModules) {
		t.Fatalf("empty config must use the built-in watch set: got %v", got)
	}
}

func TestMonitorWatchModulesAllUnknownFallsBack(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{MonitorModules: []string{"totally_bogus", "also_bogus"}}
	got := s.monitorWatchModules()
	if !slices.Equal(got, DefaultMonitorWatchModules) {
		t.Fatalf("all-unknown configuration must fall back to the built-in set: got %v", got)
	}
}
