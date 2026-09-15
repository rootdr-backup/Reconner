package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestCmdiComputedMarkerPositiveAndReflectionNegative(t *testing.T) {
	withLoopbackAllowed(t)
	tests := []struct {
		name        string
		execute     bool
		wantFinding int
	}{
		{name: "shell evaluates arithmetic", execute: true, wantFinding: 1},
		{name: "literal reflection is rejected", execute: false, wantFinding: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, targetID := newV3ScannerDB(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				value := r.URL.Query().Get("cmd")
				if tt.execute && strings.Contains(value, "$((1000+337))") {
					value = strings.ReplaceAll(value, "$((1000+337))", "1337")
				}
				fmt.Fprint(w, value)
			}))
			defer srv.Close()
			seedV3Parameter(t, db, targetID, srv.URL+"/run?cmd=ping", "cmd", "ping", "GET", "", "query")

			cfg := &config.Config{}
			s := NewCmdiScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil)
			if err := s.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
				t.Fatal(err)
			}
			if got := v3FindingCount(t, db, targetID, "command_injection", "/run"); got != tt.wantFinding {
				t.Fatalf("confirmed command-injection findings = %d, want %d", got, tt.wantFinding)
			}
		})
	}
}

func TestRaceDetectorPositiveAndStableNegative(t *testing.T) {
	withLoopbackAllowed(t)
	tests := []struct {
		name          string
		mixedOutcomes bool
		wantCandidate int
	}{
		{name: "multiple successes plus conflicts", mixedOutcomes: true, wantCandidate: 1},
		{name: "stable endpoint", mixedOutcomes: false, wantCandidate: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, targetID := newV3ScannerDB(t)
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if tt.mixedOutcomes && n > 3 {
					w.WriteHeader(http.StatusConflict)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			seedV3Parameter(t, db, targetID, srv.URL+"/redeem", "coupon", "PROMO", "POST", "application/x-www-form-urlencoded", "body")

			cfg := &config.Config{}
			s := NewRaceScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil)
			if err := s.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
				t.Fatal(err)
			}
			var got int
			if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='race_condition'`, targetID).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tt.wantCandidate {
				t.Fatalf("race candidates = %d, want %d", got, tt.wantCandidate)
			}
		})
	}
}

func TestSmugglingTimingPositiveAndFastNegative(t *testing.T) {
	tests := []struct {
		name           string
		stallMalformed bool
		want           bool
	}{
		{name: "reproducible malformed framing delay", stallMalformed: true, want: true},
		{name: "all requests respond quickly", stallMalformed: false, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, targetID := newV3ScannerDB(t)
			addr, closeServer := startRawSmugglingFixture(t, tt.stallMalformed)
			defer closeServer()

			oldDeadline, oldBaseline, oldHit := smugReadDeadline, smugSlowBaseline, smugDelayHit
			smugReadDeadline, smugSlowBaseline, smugDelayHit = 90*time.Millisecond, 45*time.Millisecond, 65*time.Millisecond
			t.Cleanup(func() { smugReadDeadline, smugSlowBaseline, smugDelayHit = oldDeadline, oldBaseline, oldHit })

			cfg := &config.Config{}
			s := NewSmugglingScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil)
			got := s.testHost(context.Background(), targetID, "http://"+addr+"/", func(string, string, string) {})
			if got != tt.want {
				t.Fatalf("testHost() = %v, want %v", got, tt.want)
			}
			var candidates int
			if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='request_smuggling'`, targetID).Scan(&candidates); err != nil {
				t.Fatal(err)
			}
			if candidates != boolIntTest(tt.want) {
				t.Fatalf("smuggling candidates = %d, want %d", candidates, boolIntTest(tt.want))
			}
		})
	}
}

func startRawSmugglingFixture(t *testing.T, stallMalformed bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				line, _ := bufio.NewReader(conn).ReadString('\n')
				if stallMalformed && strings.HasPrefix(line, "POST ") {
					time.Sleep(130 * time.Millisecond)
					return
				}
				_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
			}()
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

func boolIntTest(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestPassiveDetectorFindsEvidenceAndKeepsCleanControlEmpty(t *testing.T) {
	withLoopbackAllowed(t)
	db, targetID := newV3ScannerDB(t)
	vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.18.0")
		fmt.Fprint(w, "<html><title>Index of /</title>Traceback (most recent call last) 10.1.2.3</html>")
	}))
	defer vulnerable.Close()
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, "<html><p>healthy</p></html>")
	}))
	defer clean.Close()

	cfg := &config.Config{}
	s := NewPassiveScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil)
	if got := s.analyze(context.Background(), targetID, vulnerable.URL+"/listing"); got < 5 {
		t.Fatalf("passive vulnerable fixture produced only %d observations", got)
	}
	var before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=?`, targetID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if got := s.analyze(context.Background(), targetID, clean.URL+"/healthy"); got != 0 {
		t.Fatalf("clean control produced %d observations, want 0", got)
	}
	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=?`, targetID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("clean control changed candidate count: before=%d after=%d", before, after)
	}
}
