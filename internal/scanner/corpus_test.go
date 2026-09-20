package scanner

import (
	"slices"
	"testing"
)

func TestCorpusMergeReportsDuplicatesInvalidAndPersistsOnlyCustom(t *testing.T) {
	dir := t.TempDir()
	first, err := MergeCorpus(dir, "subdomain", []string{"www", "CUSTOM", "custom", "bad host", "api-v4", ""})
	if err != nil {
		t.Fatal(err)
	}
	if first.Added != 2 || first.Duplicates != 2 || first.Invalid != 1 || first.Input != 5 {
		t.Fatalf("unexpected merge result: %+v", first)
	}
	custom := CustomCorpus(dir, "subdomain")
	if !slices.Equal(custom, []string{"custom", "api-v4"}) {
		t.Fatalf("custom corpus=%v", custom)
	}
	all := LoadCorpus(dir, "subdomain", bruteWords)
	if !slices.Contains(all, "www") || !slices.Contains(all, "custom") || !slices.Contains(all, "api-v4") {
		t.Fatalf("effective corpus missing values: %v", all)
	}

	second, err := MergeCorpus(dir, "subdomain", []string{"Api-V4", "new-zone"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Added != 1 || second.Duplicates != 1 || second.Invalid != 0 {
		t.Fatalf("second merge result: %+v", second)
	}

	removed, err := RestoreCorpus(dir, "subdomain")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 || len(CustomCorpus(dir, "subdomain")) != 0 {
		t.Fatalf("restore removed=%d custom=%v", removed, CustomCorpus(dir, "subdomain"))
	}
	if !slices.Contains(LoadCorpus(dir, "subdomain", bruteWords), "www") {
		t.Fatal("restore removed a compiled default")
	}
}

func TestCorpusMergeNormalizesFriendlyWordlistFormats(t *testing.T) {
	dir := t.TempDir()
	result, err := MergeCorpus(dir, "backup", []string{"back/.env", "/back/.env", "", "  "})
	if err != nil {
		t.Fatal(err)
	}
	if result.Input != 2 || result.Added != 1 || result.Duplicates != 1 || result.Invalid != 0 {
		t.Fatalf("unexpected normalized merge result: %+v", result)
	}
	if got := CustomCorpus(dir, "backup"); !slices.Equal(got, []string{"/back/.env"}) {
		t.Fatalf("normalized backup corpus=%v", got)
	}
	ext, err := MergeCorpus(dir, "extensions", []string{".tar.gz", "tar.gz"})
	if err != nil {
		t.Fatal(err)
	}
	if ext.Added != 1 || ext.Duplicates != 1 {
		t.Fatalf("extension normalization result=%+v", ext)
	}
}

func TestCorpusCategoryValidationProtectsProofContracts(t *testing.T) {
	cases := []struct {
		id, value string
		want      bool
	}{
		{"backup", "/back/.env", true},
		{"backup", "/../etc/passwd", false},
		{"extensions", ".tar.gz", true},
		{"extensions", "../../sh", false},
		{"xss", `<svg onload="top.document.title='%s'">`, true},
		{"xss", `<svg onload=alert(1)>`, false},
		{"ssti", `{{%d*%d}}`, true},
		{"ssti", `{{7*7}}`, false},
		{"cmdi", `;echo RCNZZ$((1000+337))ZZ`, true},
		{"cmdi", `;id`, false},
		{"redirect", `/%2f/evil.com`, true},
		{"redirect", `https://attacker.example`, false},
	}
	for _, tc := range cases {
		if got := validCorpusValue(tc.id, tc.value); got != tc.want {
			t.Errorf("validCorpusValue(%q,%q)=%v want %v", tc.id, tc.value, got, tc.want)
		}
	}
}

func TestCorpusCatalogCoversScannerFuzzAndBruteForceDictionaries(t *testing.T) {
	catalog := CorpusCatalog(t.TempDir())
	seen := make(map[string]bool, len(catalog))
	for _, category := range catalog {
		seen[category.ID] = true
	}
	for _, id := range []string{
		"subdomain", "vhost", "directory", "backup", "extensions", "parameters",
		"exposure", "graphql", "api_spec", "jwt_secrets",
		"xss", "sqli", "lfi", "ssrf", "ssti", "csti", "nosqli", "cmdi", "redirect",
	} {
		if !seen[id] {
			t.Errorf("corpus catalog missing %q", id)
		}
	}
}

func TestCSTICorpusOnlyDeduplicatesItsActuallyCompiledDefault(t *testing.T) {
	dir := t.TempDir()
	result, err := MergeCorpus(dir, "csti", []string{"{{%d*%d}}", "${%d*%d}"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || result.Duplicates != 1 {
		t.Fatalf("CSTI merge result=%+v", result)
	}
	if got := CustomCorpus(dir, "csti"); !slices.Equal(got, []string{"${%d*%d}"}) {
		t.Fatalf("CSTI custom corpus=%v", got)
	}
}

func TestNestedBackupCandidatesAreBoundedAndCoverCommonAndObservedPaths(t *testing.T) {
	got := generateNestedBackupCandidates([]string{"https://example.test/portal/", "https://example.test/products/42"})
	if len(got) > nestedBackupCandidateBudget {
		t.Fatalf("nested candidates=%d budget=%d", len(got), nestedBackupCandidateBudget)
	}
	for _, want := range []string{"/back/.env", "/backup/.git/HEAD", "/portal/.env"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing nested candidate %q", want)
		}
	}
	seen := map[string]bool{}
	for _, candidate := range got {
		if seen[candidate] {
			t.Fatalf("duplicate nested candidate %q", candidate)
		}
		seen[candidate] = true
	}
}
