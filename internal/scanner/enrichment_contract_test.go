package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestOriginResponseMatchesRequiresTargetSimilarity(t *testing.T) {
	tests := []struct {
		name                        string
		baseTitle, candidateTitle   string
		baseLength, candidateLength int
		baseHash, candidateHash     string
		want                        bool
	}{
		{name: "same title and length band", baseTitle: "Acme Portal", candidateTitle: " acme portal ", baseLength: 1000, candidateLength: 900, want: true},
		{name: "same title but unrelated length", baseTitle: "Acme Portal", candidateTitle: "acme portal", baseLength: 1000, candidateLength: 50, want: false},
		{name: "same fingerprint without title", baseLength: 1000, candidateLength: 900, baseHash: "same", candidateHash: "same", want: true},
		{name: "similar length alone", baseTitle: "", candidateTitle: "", baseLength: 1000, candidateLength: 900, want: false},
		{name: "unrelated vhost", baseTitle: "Acme", candidateTitle: "Default nginx", baseLength: 1000, candidateLength: 100, want: false},
		{name: "missing baseline", candidateTitle: "Acme", candidateLength: 1000, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := originResponseMatches(tt.baseTitle, tt.baseLength, tt.baseHash, tt.candidateTitle, tt.candidateLength, tt.candidateHash); got != tt.want {
				t.Fatalf("originResponseMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArchivedURLInScopeRejectsSiblingAndForeignHosts(t *testing.T) {
	tests := map[string]bool{
		"https://app.example.com/a?id=1":      true,
		"https://cdn.app.example.com/a?id=1":  true,
		"https://example.com/a?id=1":          false,
		"https://evil.test/a?id=1":            false,
		"https://app.example.com.evil/a?id=1": false,
	}
	for raw, want := range tests {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := archivedURLInScope("app.example.com", u); got != want {
			t.Errorf("archivedURLInScope(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestTimeMachineStoresOnlyInScopeArchivedParameters(t *testing.T) {
	db, targetID := newV3ScannerDB(t)
	oldClient := tmHTTPClient
	tmHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		body := "https://lab.local/search?q=ok\nhttps://api.lab.local/item?id=7\nhttps://evil.test/steal?token=no\n"
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	t.Cleanup(func() { tmHTTPClient = oldClient })

	s := NewTimeMachineScanner(db, nil, &config.Config{}, logger.New("error"), nil)
	if err := s.Run(context.Background(), targetID, "lab.local", func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	var inScope, foreign int
	if err := db.QueryRow(`SELECT COUNT(*) FROM parameters WHERE target_id=? AND source='timemachine'`, targetID).Scan(&inScope); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM parameters WHERE target_id=? AND url LIKE '%evil.test%'`, targetID).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if inScope != 2 || foreign != 0 {
		t.Fatalf("stored in-scope=%d foreign=%d, want 2/0", inScope, foreign)
	}
}

func TestShodanQueryDistinguishesNegativeFromFailure(t *testing.T) {
	db, _ := newV3ScannerDB(t)
	cfg := &config.Config{}
	s := NewShodanScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil)
	oldClient := shodanClient
	t.Cleanup(func() { shodanClient = oldClient })

	shodanClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	resp, err := s.queryHost(context.Background(), "secret", "203.0.113.7")
	if err != nil || resp != nil {
		t.Fatalf("404 = (%v, %v), want valid empty result", resp, err)
	}

	shodanClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader("limited")), Header: make(http.Header)}, nil
	})}
	if _, err := s.queryHost(context.Background(), "secret", "203.0.113.7"); err == nil {
		t.Fatal("429 must be reported as a failed query, not a clean negative")
	}
}
