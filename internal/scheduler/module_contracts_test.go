package scheduler

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestEveryExecutableModuleHasV3ContractAndRegressionSuite(t *testing.T) {
	seen := make(map[string]bool, len(AllModules))
	_, thisFile, _, _ := runtime.Caller(0)
	internalDir := filepath.Dir(filepath.Dir(thisFile))
	for _, module := range AllModules {
		if seen[module] {
			t.Fatalf("AllModules contains duplicate %q", module)
		}
		seen[module] = true
		contract, ok := V3ModuleContracts[module]
		if !ok {
			t.Errorf("module %q has no v3 capability contract", module)
			continue
		}
		if contract.Kind == "" || contract.Prerequisites == "" || contract.Completion == "" || contract.Proof == "" || contract.RegressionFile == "" {
			t.Errorf("module %q has an incomplete contract: %+v", module, contract)
			continue
		}
		if _, err := os.Stat(filepath.Join(internalDir, contract.RegressionFile)); err != nil {
			t.Errorf("module %q regression suite %q is unavailable: %v", module, contract.RegressionFile, err)
		}
	}
	for module := range V3ModuleContracts {
		if !seen[module] {
			t.Errorf("contract exists for non-executable/stale module %q", module)
		}
	}
}

func TestExpectedToolInventoryContainsOnlySupportedRuntimeDependencies(t *testing.T) {
	want := []string{
		"subfinder", "assetfinder", "findomain", "scilla", "asnmap",
		"puredns", "alterx", "shuffledns", "dnsx",
		"httpx", "gau", "waybackurls", "waymore", "katana", "hakrawler", "uro",
		"nuclei", "dirsearch", "feroxbuster", "subzy", "sqlmap", "python3",
	}
	if !slices.Equal(expectedTools, want) {
		t.Fatalf("expected tool inventory drifted\n got: %v\nwant: %v", expectedTools, want)
	}
	for _, retired := range []string{"nmap", "naabu", "hydra", "uncover", "dalfox", "gowitness"} {
		if slices.Contains(expectedTools, retired) {
			t.Errorf("retired/unused tool %q is still advertised", retired)
		}
	}
}
