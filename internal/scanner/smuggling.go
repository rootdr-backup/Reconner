package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// SmugglingScanner detects HTTP request-smuggling (front-end/back-end desync)
// using the SAFE time-based technique from PortSwigger's research. It never
// smuggles a real second request (which could poison another user's response);
// instead it sends a probe whose chunked/Content-Length framing, IF the two
// servers disagree, leaves the back-end blocking for more data — producing a
// long delay. A finding is raised only when the probe reproducibly times out
// while a normal request to the same host is fast, which rules out a merely slow
// server.
//
// Because it opens raw sockets and sends deliberately malformed framing, this is
// a default-OFF module (opt-in per scan).
type SmugglingScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewSmugglingScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *SmugglingScanner {
	return &SmugglingScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

const (
	smugReadDeadline = 10 * time.Second
	smugSlowBaseline = 4 * time.Second // baseline must be at least this fast
	smugDelayHit     = 8 * time.Second // probe must block at least this long
)

func (s *SmugglingScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	hosts := s.aliveRoots(ctx, targetID)
	if len(hosts) == 0 {
		return nil
	}
	logFn("info", "smuggling", fmt.Sprintf("Testing %d host(s) for HTTP request smuggling (time-based, non-destructive)...", len(hosts)))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.testHost(ctx, targetID, rawURL, logFn) {
				found.Add(1)
			}
		}(h)
	}
	wg.Wait()
	logFn("info", "smuggling", fmt.Sprintf("Smuggling done. %d desync signal(s).", found.Load()))
	return nil
}

func (s *SmugglingScanner) testHost(ctx context.Context, targetID, rawURL string, logFn LogFunc) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := u.Scheme
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostport := net.JoinHostPort(host, port)

	// Baseline: a well-formed request must be reasonably fast, else the host is
	// just slow and any "delay" is meaningless.
	baseElapsed, baseOK, err := s.sendRaw(ctx, scheme, host, hostport, baselineRequest(host))
	if err != nil || !baseOK || baseElapsed > smugSlowBaseline {
		return false
	}

	// Try CL.TE then TE.CL. Confirm any hit with a second probe to drop flukes.
	for _, probe := range []struct {
		name string
		raw  string
	}{
		{"CL.TE", clteProbe(host)},
		{"TE.CL", teclProbe(host)},
	} {
		if ctx.Err() != nil {
			return false
		}
		if s.probeTimesOut(ctx, scheme, host, hostport, probe.raw) {
			// Re-confirm: baseline still fast AND probe still blocks.
			b2, ok2, _ := s.sendRaw(ctx, scheme, host, hostport, baselineRequest(host))
			if !ok2 || b2 > smugSlowBaseline {
				continue
			}
			if !s.probeTimesOut(ctx, scheme, host, hostport, probe.raw) {
				continue
			}
			ev := fmt.Sprintf(
				"Time-based HTTP request smuggling (%s desync): a probe with conflicting Content-Length/Transfer-Encoding framing blocked the back-end for >%s while a normal request returned in %s. Strongly indicates front-end/back-end desync.",
				probe.name, smugDelayHit, baseElapsed.Round(time.Millisecond))
			s.store(targetID, rawURL, probe.name, ev)
			logFn("warn", "smuggling", fmt.Sprintf("Request smuggling (%s): %s", probe.name, rawURL))
			return true
		}
	}
	return false
}

// probeTimesOut returns true when the probe blocks past the delay threshold
// (i.e. no response byte arrived before smugDelayHit).
func (s *SmugglingScanner) probeTimesOut(ctx context.Context, scheme, host, hostport, raw string) bool {
	elapsed, gotResp, err := s.sendRaw(ctx, scheme, host, hostport, raw)
	if err != nil {
		return false
	}
	// Blocked: either the read hit our deadline (no response) or first byte took
	// far longer than a healthy baseline.
	return !gotResp && elapsed >= smugDelayHit
}

// sendRaw opens a raw connection, writes the exact bytes, and measures time to
// the first response byte. gotResp is false if the read deadline elapsed first.
func (s *SmugglingScanner) sendRaw(ctx context.Context, scheme, host, hostport, raw string) (time.Duration, bool, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	var conn net.Conn
	var err error
	if scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", hostport, &tls.Config{
			InsecureSkipVerify: true, // scanning arbitrary targets; cert validity is irrelevant here
			ServerName:         host,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", hostport)
	}
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(smugReadDeadline))
	start := time.Now()
	if _, err = conn.Write([]byte(raw)); err != nil {
		return 0, false, err
	}
	buf := make([]byte, 1)
	_, rerr := conn.Read(buf)
	elapsed := time.Since(start)
	if rerr != nil {
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			return elapsed, false, nil // blocked until deadline → no response
		}
		return elapsed, false, nil // connection error also counts as "no clean response"
	}
	return elapsed, true, nil
}

func baselineRequest(host string) string {
	return "GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; ReconBot/1.0)\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
}

// CL.TE: the body is a COMPLETE, valid chunked message ("1\r\nA\r\n0\r\n\r\n").
// A non-desync server responds fast whether it honours CL or TE. But if the
// front-end uses Content-Length (4) it forwards only "1\r\nA" and drops the
// terminating "0\r\n\r\n"; a back-end using Transfer-Encoding then blocks waiting
// for the chunk terminator that never arrives → delay. Using a valid body is
// what keeps this from false-positiving on ordinary TE servers.
func clteProbe(host string) string {
	return "POST / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; ReconBot/1.0)\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"1\r\nA\r\n0\r\n\r\n"
}

// TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length. The
// front-end sees the "0" terminating chunk and forwards "0\r\n\r\n"; the back-end
// (CL=6) waits for 6 bytes it never receives → delay.
func teclProbe(host string) string {
	return "POST / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (compatible; ReconBot/1.0)\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\nX"
}

func (s *SmugglingScanner) aliveRoots(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id = ? AND COALESCE(source,'probe') = 'probe' AND status_code BETWEEN 200 AND 499
		ORDER BY url LIMIT 150`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) != nil {
			continue
		}
		if b := hostBaseScan(u); b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}

func (s *SmugglingScanner) store(targetID, url, variant, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "request_smuggling", Subtype: variant, Severity: "high",
		URL: url, Method: "RAW", Location: "connection", Payload: variant + " desync",
		Evidence: evidence, Source: "smuggling", DetectionMethod: "desync-differential",
		Confidence: 75, Priority: 300, Verdict: CandDetected,
	})
}
