package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cdppage "github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// browserXSSConfirmer proves reflected XSS by loading the candidate URL in a real
// HEADLESS Chromium and observing whether the injected payload ACTUALLY EXECUTES.
// The proof is execution-based, not heuristic: each payload's JavaScript sets
// document.title to a fresh random nonce, and we read the title back afterwards.
// Only code that truly ran could have written the random nonce — a raw reflection
// of the payload text cannot set document.title — so this is reflection-proof and
// ALSO works on modern, client-rendered / SPA apps where the reflection only
// appears after JavaScript runs (the raw-HTML parser sees nothing).
//
// Scope note: this catches XSS that becomes executable once the page renders
// (server-reflected-into-DOM, JS-templated, framework-hydrated). It is NOT a
// taint-tracking DOM-XSS source→sink analyzer — that is intentionally out of
// scope for now.
//
// Resource model (this is a rewrite of an earlier design that leaked disk):
//   - ONE headless browser process and ONE tab for the whole scanner lifetime;
//     every candidate is confirmed by RE-NAVIGATING that single tab. The earlier
//     design spawned a browser — and a /tmp/chromedp-runner* user-data-dir — per
//     payload per candidate, cleaned only on a graceful browser exit, so a real
//     scan left thousands behind until the host ran out of disk/inodes.
//   - The user-data-dir is an explicit path we create and delete ourselves, so
//     Chromium never creates its own auto temp dir and cleanup does not depend on
//     any graceful-exit path. sweepStaleBrowserProfiles() also removes profiles
//     orphaned by a previous hard kill at process start.
//
// Detection remains title-based because dialog events are not reliable enough to
// be the sole proof across repeated navigations. The proof payload also calls
// alert('reconner') for a conventional human-visible PoC; the title nonce is set
// first, and the dialog is automatically dismissed so the reusable tab cannot be
// left blocked.
//
// Best-effort: if no Chromium/Chrome binary is present the confirmer disables
// itself and callers fall back to the browserless verifier, so a scan never fails
// for lack of a browser.
type browserXSSConfirmer struct {
	chromePath  string
	dataDir     string // active explicit user-data-dir we own and delete
	profileBase string // non-empty for managed, restart-safe per-session profiles
	profileSeq  uint64

	mu          sync.Mutex
	alloc       context.Context
	allocCancel context.CancelFunc
	tab         context.Context // the single reused tab
	tabCancel   context.CancelFunc
	process     *os.Process
	activeOwner string
	activeLease uint64
	nextLease   uint64

	// one navigation at a time: the single tab cannot be driven concurrently.
	navGate chan struct{}

	loaderOnce  sync.Once
	loaderURL   string
	loaderClose func()
}

var (
	xssBrowserOnce sync.Once
	xssBrowserMu   sync.RWMutex
	xssBrowserInst *browserXSSConfirmer
	domReflectMemo = struct {
		sync.Mutex
		entries map[string]domReflectEntry
	}{entries: map[string]domReflectEntry{}}
)

type domReflectEntry struct {
	reflected bool
	trace     string
	at        time.Time
}

const (
	domReflectTTL        = 10 * time.Minute
	domReflectMaxEntries = 20000
)

const xssProfilePrefix = "reconner-xss-"

const xssBrowserAbortWait = 2 * time.Second

type xssBrowserOwnerKey struct{}

// WithXSSBrowserOwner associates browser work with one scheduler task. The
// process-wide browser executes one navigation at a time, so this owner lets an
// operator skip kill only the session currently serving that task. Waiting
// tasks are left alone and rebuild a fresh session when they acquire the gate.
func WithXSSBrowserOwner(ctx context.Context, owner string) context.Context {
	if strings.TrimSpace(owner) == "" {
		return ctx
	}
	return context.WithValue(ctx, xssBrowserOwnerKey{}, owner)
}

func xssBrowserOwner(ctx context.Context) string {
	owner, _ := ctx.Value(xssBrowserOwnerKey{}).(string)
	return owner
}

// getXSSBrowser returns the process-wide confirmer, or nil when disabled / no
// browser is available. Enabled unless RECONNER_NO_XSS_BROWSER is set.
func getXSSBrowser() *browserXSSConfirmer {
	xssBrowserOnce.Do(func() {
		if os.Getenv("RECONNER_NO_XSS_BROWSER") != "" {
			return
		}
		p := findChromePath()
		if p == "" {
			return
		}
		sweepStaleBrowserProfiles() // clean anything a prior hard-kill orphaned
		base := filepath.Join(os.TempDir(), xssProfilePrefix+strconv.Itoa(os.Getpid()))
		xssBrowserMu.Lock()
		xssBrowserInst = &browserXSSConfirmer{
			chromePath:  p,
			profileBase: base,
			navGate:     make(chan struct{}, 1),
		}
		xssBrowserMu.Unlock()
	})
	xssBrowserMu.RLock()
	browser := xssBrowserInst
	xssBrowserMu.RUnlock()
	return browser
}

// sweepStaleBrowserProfiles removes reconner XSS browser profiles left in TempDir
// by a previous process that was hard-killed before Close() could run. It only
// touches our own prefix, never other tools' temp dirs.
func sweepStaleBrowserProfiles() {
	matches, _ := filepath.Glob(filepath.Join(os.TempDir(), xssProfilePrefix+"*"))
	for _, m := range matches {
		_ = os.RemoveAll(m)
	}
}

// findChromePath locates a headless-capable Chromium/Chrome binary.
func findChromePath() string {
	if p := os.Getenv("RECONNER_CHROME"); p != "" {
		if browserBinaryWorks(p) {
			return p
		}
	}
	for _, name := range []string{
		"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "headless-shell",
	} {
		if p, err := exec.LookPath(name); err == nil && browserBinaryWorks(p) {
			return p
		}
	}
	// Common absolute locations (containers / Playwright bundles).
	for _, p := range []string{
		"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
		"/snap/bin/chromium", "/opt/google/chrome/chrome",
		// macOS app bundles. Reconner is frequently run directly from a Mac where
		// Chrome is not exported on PATH; omitting these silently disabled every
		// reflected/DOM runtime proof even though a browser was installed.
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
	} {
		if browserBinaryWorks(p) {
			return p
		}
	}
	return ""
}

// browserBinaryWorks rejects stale symlinks/wrappers that exist on disk but can
// no longer launch their app bundle. Selecting one of those used to disable all
// runtime XSS proof silently even when a valid Chrome binary appeared later in
// the search list. Every Chromium-family binary supports --version and exits
// quickly, making this a cheap one-time startup check.
func browserBinaryWorks(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() { // #nosec G703 -- candidates come only from operator-controlled env, LookPath, or fixed paths
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version") // #nosec G702 -- operator-selected browser path is executed without a shell and with one fixed argument
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run() == nil && ctx.Err() == nil
}

// ensureTab lazily starts the single shared browser + tab, rebuilding if it
// died. Browser startup deliberately happens without b.mu held: allocator
// startup is external process I/O and may wedge, while Skip must always be able
// to acquire the mutex, detach the lease, and cancel/kill the session.
func (b *browserXSSConfirmer) ensureTab(lease uint64) (context.Context, bool) {
	b.mu.Lock()
	if b.tab != nil && b.tab.Err() == nil {
		tab := b.tab
		b.mu.Unlock()
		return tab, true
	}
	oldTabCancel := b.tabCancel
	if b.tabCancel != nil {
		b.tab, b.tabCancel = nil, nil
	}
	if b.alloc == nil || b.alloc.Err() != nil {
		if b.dataDir == "" {
			b.profileSeq++
			b.dataDir = fmt.Sprintf("%s-%d", b.profileBase, b.profileSeq)
		}
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(b.chromePath),
			chromedp.UserDataDir(b.dataDir), // explicit → Chromium makes no auto temp dir
			chromedp.Flag("headless", true),
			chromedp.Flag("no-sandbox", true), // scans run as root in the appliance
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("disable-background-networking", true),
			chromedp.NoDefaultBrowserCheck,
			chromedp.ModifyCmdFunc(configureXSSBrowserProcess),
		)
		b.alloc, b.allocCancel = chromedp.NewExecAllocator(context.Background(), opts...)
	}
	alloc := b.alloc
	b.mu.Unlock()
	if oldTabCancel != nil {
		oldTabCancel()
	}

	// Silence chromedp's CDP event logger: a newer Chromium emits enum values (e.g.
	// network IPAddressSpace "Loopback") that this cdproto version can't unmarshal,
	// which is harmless but would otherwise spam scan logs with ERROR lines.
	noop := func(string, ...interface{}) {}
	tabCtx, tabCancel := chromedp.NewContext(alloc,
		chromedp.WithErrorf(noop), chromedp.WithLogf(noop))
	chromedp.ListenTarget(tabCtx, func(event any) {
		if _, ok := event.(*cdppage.EventJavascriptDialogOpening); !ok {
			return
		}
		// Never leave the shared confirmation tab blocked by the proof popup (or
		// by an application dialog encountered during navigation).
		go func() {
			_ = chromedp.Run(tabCtx, cdppage.HandleJavaScriptDialog(true))
		}()
	})

	// Bind the primary target to this long-lived context by running the first action
	// on tabCtx DIRECTLY. chromedp ties the target's lifecycle to the context of its
	// first Run; if that first Run is a WithTimeout child that then gets cancelled,
	// the target is torn down and every later navigation silently fails to load
	// (never even reaching the server). Per-fire navigations run on short-lived
	// children of b.tab, which is safe precisely because the target lives on b.tab.
	if err := chromedp.Run(tabCtx); err != nil { // force the browser to start now
		tabCancel()
		return nil, false
	}
	b.mu.Lock()
	// Abort may have detached this allocator/lease while startup was in flight.
	// Never publish that stale browser as the session for a later phase.
	if b.alloc != alloc || b.activeLease != lease {
		b.mu.Unlock()
		tabCancel()
		return nil, false
	}
	b.tab, b.tabCancel = tabCtx, tabCancel
	if c := chromedp.FromContext(tabCtx); c != nil && c.Browser != nil {
		b.process = c.Browser.Process()
	}
	tab := b.tab
	b.mu.Unlock()
	return tab, true
}

// acquireNavigation serializes access to the reusable tab and records which
// scheduler task currently owns it. Abort replaces the gate, so even a broken
// chromedp goroutine holding the old gate cannot block future phases forever.
func (b *browserXSSConfirmer) acquireNavigation(parent context.Context) (chan struct{}, uint64, bool) {
	if b == nil {
		return nil, 0, false
	}
	for {
		b.mu.Lock()
		if b.navGate == nil {
			b.navGate = make(chan struct{}, 1)
		}
		gate := b.navGate
		b.mu.Unlock()
		select {
		case gate <- struct{}{}:
		case <-parent.Done():
			return nil, 0, false
		}

		b.mu.Lock()
		if gate != b.navGate {
			b.mu.Unlock()
			<-gate
			continue
		}
		b.nextLease++
		lease := b.nextLease
		b.activeLease = lease
		b.activeOwner = xssBrowserOwner(parent)
		b.mu.Unlock()
		return gate, lease, true
	}
}

func (b *browserXSSConfirmer) releaseNavigation(gate chan struct{}, lease uint64) {
	b.mu.Lock()
	if b.activeLease == lease {
		b.activeLease = 0
		b.activeOwner = ""
	}
	b.mu.Unlock()
	<-gate
}

// operationContext keeps chromedp's executor from the long-lived tab while
// linking cancellation to the scheduler phase. The same hard deadline also
// destroys the browser process: cancelling a CDP command alone is not enough
// when Chromium or its transport is wedged.
func (b *browserXSSConfirmer) operationContext(parent, tab context.Context, timeout time.Duration, lease uint64) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(tab, timeout)
	owner := xssBrowserOwner(parent)
	abort := func() {
		cancel()
		b.abortSession(owner, lease)
	}
	stopParent := context.AfterFunc(parent, abort)
	hardTimer := time.AfterFunc(timeout, abort)
	return ctx, func() {
		stopParent()
		hardTimer.Stop()
		cancel()
	}
}

// AbortXSSBrowserOwner force-stops the active Chromium process only when it is
// currently serving owner. It is safe to call from the scheduler's Skip path;
// a scan merely waiting for the navigation gate has no process to kill.
func AbortXSSBrowserOwner(owner string) bool {
	if strings.TrimSpace(owner) == "" {
		return false
	}
	xssBrowserMu.RLock()
	browser := xssBrowserInst
	xssBrowserMu.RUnlock()
	if browser == nil {
		return false
	}
	return browser.abortSession(owner, 0)
}

// abortSession is deliberately hard and non-blocking after process cleanup.
// chromedp's allocator cancel waits for cmd.Wait and has historically hung when
// Chromium was unhealthy, so it runs behind a bounded wait after the entire
// isolated process group has received SIGKILL.
func (b *browserXSSConfirmer) abortSession(owner string, lease uint64) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	if lease != 0 && b.activeLease != lease {
		b.mu.Unlock()
		return false
	}
	if owner != "" && b.activeOwner != owner {
		b.mu.Unlock()
		return false
	}
	tabCancel, allocCancel := b.tabCancel, b.allocCancel
	process, dataDir := b.process, b.dataDir
	b.tab, b.tabCancel = nil, nil
	b.alloc, b.allocCancel = nil, nil
	b.process = nil
	if b.profileBase != "" {
		b.dataDir = ""
	}
	// Detach future work from a goroutine that might never release the old gate.
	b.navGate = make(chan struct{}, 1)
	b.activeLease = 0
	b.activeOwner = ""
	b.mu.Unlock()

	killXSSBrowserProcess(process)
	if tabCancel != nil || allocCancel != nil {
		done := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			if tabCancel != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tabCancel()
				}()
			}
			if allocCancel != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					allocCancel()
				}()
			}
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(xssBrowserAbortWait):
		}
	}
	if dataDir != "" {
		_ = os.RemoveAll(dataDir)
	}
	return tabCancel != nil || allocCancel != nil || process != nil
}

// Close tears down the browser/allocator and removes the profile dir. Idempotent.
func (b *browserXSSConfirmer) Close() {
	if b == nil {
		return
	}
	b.abortSession("", 0)
	b.mu.Lock()
	if b.loaderClose != nil {
		b.loaderClose()
		b.loaderClose = nil
	}
	b.mu.Unlock()
}

func (b *browserXSSConfirmer) scriptLoaderPage() string {
	b.loaderOnce.Do(func() {
		// A real loopback HTTP origin avoids opaque data:/about:blank Private
		// Network Access restrictions while remaining isolated from the target.
		// It models the attack faithfully: an external page includes the reflected
		// endpoint as a classic cross-origin <script src> resource.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			if r.URL.Path == "/post-message" {
				payloadJSON, _ := json.Marshal(r.URL.Query().Get("payload"))
				_, _ = fmt.Fprintf(w, "<script>parent.postMessage(%s, '*')</script>", payloadJSON)
				return
			}
			_, _ = w.Write([]byte("<html><head><title>reconner</title></head><body></body></html>"))
		}))
		b.loaderURL = srv.URL
		b.loaderClose = srv.Close
	})
	return b.loaderURL
}

// top.postMessage is permitted across origins, unlike top.document.title. This
// keeps the title proof while removing a systematic false negative for payloads
// that execute inside a cross-origin child frame.
const xssBrowserProofExpression = `(document.title='%[1]s',top.postMessage({__reconnerXSSProof:'%[1]s'},'*'),alert('reconner'))`

func addXSSPopupProof(templates []string) []string {
	out := make([]string, 0, len(templates))
	for _, tmpl := range templates {
		out = append(out, strings.ReplaceAll(tmpl, `top.document.title='%s'`, xssBrowserProofExpression))
	}
	return out
}

// xssBrowserPayloads are context-spanning proof payloads. Executed JavaScript
// first sets document.title to the random nonce (%s), which is the machine-
// verifiable signal, and then shows alert('reconner') as the conventional visual
// PoC. Neither operation reads or transmits application data.
func xssBrowserPayloads() []string {
	return addXSSPopupProof([]string{
		// Clean HTML vectors (raw-string quotes do not need backslashes).
		`<img src=x onerror="top.document.title='%s'">`,
		`<img src=x onerror=top.document.title='%s'>`,
		`"><img src=x onerror="top.document.title='%s'">`,
		`"><svg onload="top.document.title='%s'">`,
		`'><img src=x onerror="top.document.title='%s'">`,
		` autofocus onfocus="top.document.title='%s'" x=`,
		`"><details open ontoggle="top.document.title='%s'">`,
		`"><input autofocus onfocus="top.document.title='%s'">`,
		`</textarea><svg onload="top.document.title='%s'">`,
		`</title><svg onload="top.document.title='%s'">`,
		`</noscript><svg onload="top.document.title='%s'">`,
		`</xmp><svg onload="top.document.title='%s'">`,
		`</noembed><svg onload="top.document.title='%s'">`,
		`</iframe><svg onload="top.document.title='%s'">`,
		`</style><svg onload="top.document.title='%s'">`,
		`--><svg onload="top.document.title='%s'">`,
		`<iframe srcdoc="<svg onload=top.document.title='%s'>"></iframe>`,
		`<video><source onerror="top.document.title='%s'">`,
		// JavaScript string/expression/template contexts.
		`";top.document.title='%s';//`,
		"${top.document.title='%s'}",
		`;top.document.title='%s';//`,
		"`;top.document.title='%s';//",
		// URL attributes; the browser confirmer activates javascript: links.
		`javascript:top.document.title='%s'`,
		// Raw-text/script breakouts.
		`</script><script>top.document.title='%s'</script>`,
		`';top.document.title='%s';//`,
		`"><script>top.document.title='%s'</script>`,
	})
}

// xssBrowserPayloadsForAnalysis keeps runtime verification context-aware. The
// raw reflection analyzer has already told us whether the value is HTML text, a
// specific quote-delimited attribute, JavaScript, CSS, URL, comment or RCDATA.
// Replaying all ~20 cross-context payloads in Chromium after that classification
// was redundant and made one safe candidate cost tens of serialized navigations.
// The selected ladders retain multiple syntactic/WAF variants for the relevant
// context; unknown DOM-only contexts still receive the complete ladder.
func xssBrowserPayloadsForAnalysis(a *ReflectionAnalysis) []string {
	if a == nil || a.Context == "" || a.Context == CtxNone {
		return xssBrowserPayloads()
	}
	clean := `<img src=x onerror="top.document.title='%s'">`
	svg := `<svg onload="top.document.title='%s'">`
	doubleBreak := `"><img src=x onerror="top.document.title='%s'">`
	singleBreak := `'><img src=x onerror="top.document.title='%s'">`
	var out []string
	switch a.Context {
	case CtxHTMLText:
		out = []string{
			clean,
			svg,
			`<details open ontoggle="top.document.title='%s'">`,
			`<video><source onerror="top.document.title='%s'">`,
			`<input autofocus onfocus="top.document.title='%s'">`,
			`</script><script>top.document.title='%s'</script>`,
		}
	case CtxQuotedAttr, CtxURL:
		if a.Context == CtxURL && a.URLScheme {
			out = append(out, `javascript:top.document.title='%s'`)
		}
		if a.Quote == '\'' {
			out = append(out, singleBreak, `' autofocus onfocus="top.document.title='%s'" x='`)
		} else {
			out = append(out, doubleBreak, `" autofocus onfocus="top.document.title='%s'" x="`)
		}
		out = append(out, `"><svg onload="top.document.title='%s'">`, `</script><script>top.document.title='%s'</script>`)
	case CtxUnquotedAttr:
		out = []string{` autofocus onfocus="top.document.title='%s'" x=`, `><svg onload="top.document.title='%s'">`, `><img src=x onerror="top.document.title='%s'">`}
	case CtxEventHandler, CtxJSString:
		if a.JSQuote == '\'' {
			out = []string{`';top.document.title='%s';//`, `');top.document.title='%s';//`}
			if strings.Contains(a.Escaped, "'") && strings.Contains(a.Surviving, `\`) {
				out = append([]string{`\';top.document.title='%s';//`}, out...)
			}
		} else if a.JSQuote == '`' {
			out = []string{"`;top.document.title='%s';//", "${top.document.title='%s'}"}
			if strings.Contains(a.Escaped, "`") && strings.Contains(a.Surviving, `\`) {
				out = append([]string{"\\`;top.document.title='%s';//"}, out...)
			}
		} else {
			out = []string{`";top.document.title='%s';//`, `);top.document.title='%s';//`}
			if strings.Contains(a.Escaped, `"`) && strings.Contains(a.Surviving, `\`) {
				out = append([]string{`\";top.document.title='%s';//`}, out...)
			}
		}
		if a.Context == CtxEventHandler && a.Quote != 0 && strings.Contains(a.Surviving, string(a.Quote)) {
			if a.Quote == '\'' {
				out = append(out, singleBreak)
			} else {
				out = append(out, doubleBreak)
			}
		}
		out = append(out, `</script><script>top.document.title='%s'</script>`)
	case CtxJSExpr:
		out = []string{`;top.document.title='%s';//`, `${top.document.title='%s'}`, `</script><script>top.document.title='%s'</script>`}
	case CtxCSS:
		out = []string{`</style><svg onload="top.document.title='%s'">`}
	case CtxComment:
		out = []string{`--><svg onload="top.document.title='%s'">`}
	case CtxRCDATA, CtxRAWTEXT:
		if a.CloseTag != "" {
			out = []string{a.CloseTag + `<svg onload="top.document.title='%s'">`}
		} else {
			out = []string{`</textarea><svg onload="top.document.title='%s'">`, `</title><svg onload="top.document.title='%s'">`}
		}
	case CtxSrcDoc:
		out = []string{
			`&lt;svg onload=&quot;top.document.title='%s'&quot;&gt;`,
			clean,
		}
		if a.Quote == '\'' {
			out = append(out, singleBreak)
		} else {
			out = append(out, doubleBreak)
		}
	default:
		return xssBrowserPayloads()
	}
	seen := map[string]bool{}
	deduped := out[:0]
	for _, p := range out {
		if p != "" && !seen[p] {
			seen[p] = true
			deduped = append(deduped, p)
		}
	}
	return addXSSPopupProof(deduped)
}

func randNonce() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "RCNX" + hex.EncodeToString(b[:])
}

// Confirm loads rawURL with each payload injected into param and reports the first
// payload that actually executes in the browser. The returned payload is the exact
// proof that ran: it sets a nonce title and shows alert('reconner'), without reading
// or sending application data. ok=false means no execution was observed (not
// vulnerable, or safely encoded/escaped by the app).
func (b *browserXSSConfirmer) Confirm(parent context.Context, rawURL, param string) (payload string, ok bool) {
	return b.ConfirmInsertion(parent, insertionPoint{URL: rawURL, Param: param, Method: "GET", Location: "query"}, nil)
}

// ConfirmInsertion proves execution using the insertion point's real placement.
// Query-only navigation silently missed path parameters and POST forms; those now
// reach Chromium as a real path navigation or top-level form submission. JSON
// bodies are not emulated as document navigations because fetch() does not render
// a JSON response and pretending it does would create false positives.
func (b *browserXSSConfirmer) ConfirmInsertion(parent context.Context, ip insertionPoint, auth map[string]string) (payload string, ok bool) {
	return b.ConfirmInsertionWithAnalysis(parent, ip, auth, nil)
}

func browserFormValues(ip insertionPoint, value string) url.Values {
	values := url.Values{}
	for k, v := range ip.Siblings {
		values.Set(k, v)
	}
	values.Set(ip.Param, value)
	return values
}

// ConfirmInsertionWithAnalysis is ConfirmInsertion with an optional reflection
// context. Passing the context avoids cross-context browser payload spray while
// preserving the full ladder for DOM-only/unknown sinks.
func (b *browserXSSConfirmer) ConfirmInsertionWithAnalysis(parent context.Context, ip insertionPoint, auth map[string]string, a *ReflectionAnalysis) (payload string, ok bool) {
	return b.ConfirmInsertionWithAnalysisAndTemplates(parent, ip, auth, a, nil)
}

// ConfirmInsertionWithAnalysisAndTemplates appends validated operator templates
// to the context-aware built-ins. Every custom template is still subject to the
// same real-browser random-title proof; adding a payload cannot weaken the XSS
// verifier into a reflection-only detector.
func (b *browserXSSConfirmer) ConfirmInsertionWithAnalysisAndTemplates(parent context.Context, ip insertionPoint, auth map[string]string, a *ReflectionAnalysis, custom []string) (payload string, ok bool) {
	var analyses []ReflectionAnalysis
	if a != nil {
		analyses = []ReflectionAnalysis{*a}
	}
	return b.ConfirmInsertionWithAnalysesAndTemplates(parent, ip, auth, analyses, custom)
}

func xssBrowserTemplatesForAnalyses(analyses []ReflectionAnalysis) []string {
	var templates []string
	if len(analyses) == 0 {
		templates = xssBrowserPayloads()
	} else {
		for i := range analyses {
			templates = append(templates, xssBrowserPayloadsForAnalysis(&analyses[i])...)
		}
	}
	seen := make(map[string]bool, len(templates))
	deduped := templates[:0]
	for _, template := range templates {
		if template != "" && !seen[template] {
			seen[template] = true
			deduped = append(deduped, template)
		}
	}
	return deduped
}

// ConfirmInsertionWithAnalysesAndTemplates builds one bounded, deduplicated
// ladder across every distinct reflection context for the parameter. This keeps
// the single-browser execution model intact while avoiding the old false
// negative where the first/strongest reflection hid a second executable sink.
func (b *browserXSSConfirmer) ConfirmInsertionWithAnalysesAndTemplates(parent context.Context, ip insertionPoint, auth map[string]string, analyses []ReflectionAnalysis, custom []string) (payload string, ok bool) {
	if b == nil {
		return "", false
	}
	templates := xssBrowserTemplatesForAnalyses(analyses)
	seen := make(map[string]bool, len(templates)+len(custom))
	for _, template := range templates {
		seen[template] = true
	}
	if len(custom) > 64 {
		custom = custom[:64]
	}
	for _, template := range custom {
		if !validCorpusValue("xss", template) {
			continue
		}
		// Keep the stable stored/UI contract, but give custom templates the
		// same popup and cross-frame proof channel at execution time. Deduplicate
		// after this normalization so an operator cannot replay a built-in.
		runtimeTemplate := strings.ReplaceAll(template, `top.document.title='%s'`, xssBrowserProofExpression)
		if !seen[runtimeTemplate] {
			seen[runtimeTemplate] = true
			templates = append(templates, runtimeTemplate)
		}
	}
	for _, tmpl := range templates {
		if parent.Err() != nil {
			return "", false
		}
		nonce := randNonce()
		pl := fmt.Sprintf(tmpl, nonce)
		method := strings.ToUpper(strings.TrimSpace(ip.Method))
		fired := false
		switch {
		case method == "POST" && strings.Contains(strings.ToLower(ip.ContentType), "json"):
			continue
		case method == "POST":
			fired = b.fireForm(parent, ip.URL, browserFormValues(ip, pl), auth, nonce)
		default:
			req, err := buildInjectedRequest(parent, ip, pl, auth)
			if err == nil {
				fired = b.fireWithHeaders(parent, req.URL.String(), auth, nonce)
			}
		}
		if fired {
			return pl, true
		}
	}
	return "", false
}

// ConfirmScriptResource proves reflected XSS in a JavaScript/JSONP endpoint by
// loading the injected response as an actual external script. Navigating directly
// to application/javascript only displays source and used to produce a systematic
// miss. The browser now evaluates the resource in a clean document and the same
// random-title nonce makes reflection alone insufficient as proof.
func (b *browserXSSConfirmer) ConfirmScriptResource(parent context.Context, ip insertionPoint, auth map[string]string) (payload string, ok bool) {
	if b == nil || strings.EqualFold(strings.TrimSpace(ip.Method), "POST") {
		return "", false
	}
	for _, tmpl := range addXSSPopupProof([]string{
		`top.document.title='%s'//`,
		`;top.document.title='%s';//`,
		`');top.document.title='%s';//`,
		`"};top.document.title='%s';//`,
		`);top.document.title='%s';//`,
	}) {
		if parent.Err() != nil {
			return "", false
		}
		nonce := randNonce()
		pl := fmt.Sprintf(tmpl, nonce)
		req, err := buildInjectedRequest(parent, ip, pl, auth)
		if err != nil {
			continue
		}
		if b.fireScriptResource(parent, req.URL.String(), auth, nonce) {
			return pl, true
		}
	}
	return "", false
}

// DOMReflects navigates a real browser to rawURL with a unique canary injected in
// param, lets client JS run, then reports whether the canary appears in the RENDERED
// DOM (document.documentElement.outerHTML). This catches SPA / client-rendered
// reflections that never appear in the raw HTML the HTTP checker sees — the reason
// mature JS sites looked "0 reflected". Bounded by the caller's budget.
func (b *browserXSSConfirmer) DOMReflects(parent context.Context, rawURL, param string) bool {
	return b.DOMReflectsInsertion(parent, insertionPoint{URL: rawURL, Param: param, Method: "GET", Location: "query"}, nil)
}

func domReflectKey(ip insertionPoint, auth map[string]string) string {
	keys := make([]string, 0, len(ip.Siblings))
	for k := range ip.Siblings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var shape strings.Builder
	for _, k := range keys {
		shape.WriteString(k)
		shape.WriteByte('=')
		shape.WriteString(ip.Siblings[k])
		shape.WriteByte(0)
	}
	return ip.URL + "\x00" + insertionIdentity(ip) + "\x00" + shape.String() + "\x00" + authFingerprint(auth)
}

func cachedDOMReflection(key string) (bool, bool) {
	domReflectMemo.Lock()
	defer domReflectMemo.Unlock()
	e, ok := domReflectMemo.entries[key]
	if !ok {
		return false, false
	}
	if time.Since(e.at) >= domReflectTTL {
		delete(domReflectMemo.entries, key)
		return false, false
	}
	return e.reflected, true
}

func storeDOMReflection(key string, reflected bool, trace ...string) {
	domReflectMemo.Lock()
	defer domReflectMemo.Unlock()
	if len(domReflectMemo.entries) >= domReflectMaxEntries {
		now := time.Now()
		for k, e := range domReflectMemo.entries {
			if now.Sub(e.at) >= domReflectTTL {
				delete(domReflectMemo.entries, k)
			}
		}
		if len(domReflectMemo.entries) >= domReflectMaxEntries {
			domReflectMemo.entries = map[string]domReflectEntry{}
		}
	}
	entry := domReflectEntry{reflected: reflected, at: time.Now()}
	if len(trace) > 0 {
		entry.trace = strings.TrimSpace(trace[0])
	}
	domReflectMemo.entries[key] = entry
}

func cachedDOMRuntimeTrace(key string) string {
	domReflectMemo.Lock()
	defer domReflectMemo.Unlock()
	e, ok := domReflectMemo.entries[key]
	if !ok || time.Since(e.at) >= domReflectTTL {
		return ""
	}
	return e.trace
}

func (b *browserXSSConfirmer) RuntimeTrace(ip insertionPoint, auth map[string]string) string {
	return cachedDOMRuntimeTrace(domReflectKey(ip, auth))
}

// DOMReflectsInsertion performs one inert rendered-DOM canary navigation before
// the expensive execution ladder. Negative results are memoized briefly so the
// param-reflection and XSS modules do not repeat the same browser work.
func (b *browserXSSConfirmer) DOMReflectsInsertion(parent context.Context, ip insertionPoint, auth map[string]string) bool {
	if b == nil {
		return false
	}
	loc := insertionLocation(ip)
	method := strings.ToUpper(strings.TrimSpace(ip.Method))
	if loc == "json" || loc == "multipart" || loc == "xml" || (method != "" && method != "GET" && method != "POST") {
		return false
	}
	key := domReflectKey(ip, auth)
	if reflected, ok := cachedDOMReflection(key); ok {
		return reflected
	}
	canary := randNonce()
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}
	ctx, cancel := b.operationContext(parent, tab, 12*time.Second, lease)
	defer cancel()
	removeInstrumentation := installRuntimeDOMInstrumentation(ctx, tab, canary)
	defer removeInstrumentation()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{ip.URL}, auth)
	defer stopHeaders()
	var dom string
	if method == "POST" {
		parsed, err := url.Parse(ip.URL)
		if err == nil {
			origin := parsed.Scheme + "://" + parsed.Host + "/"
			actionJSON, _ := json.Marshal(ip.URL)
			valuesJSON, _ := json.Marshal(browserFormValues(ip, canary))
			script := fmt.Sprintf(`(()=>{const a=%s,v=%s,f=document.createElement('form');f.method='POST';f.action=a;for(const [k,vs] of Object.entries(v)){for(const x of vs){const i=document.createElement('input');i.type='hidden';i.name=k;i.value=x;f.appendChild(i)}}document.body.appendChild(f);f.submit()})()`, actionJSON, valuesJSON)
			actions := append(headerActions, chromedp.Navigate(origin), chromedp.Evaluate(script, nil), chromedp.Sleep(800*time.Millisecond), chromedp.Evaluate(`document.documentElement.outerHTML`, &dom))
			_ = chromedp.Run(ctx, actions...)
		}
	} else if req, err := buildInjectedRequest(ctx, ip, canary, auth); err == nil {
		actions := append(headerActions, chromedp.Navigate(req.URL.String()), chromedp.Sleep(800*time.Millisecond), chromedp.Evaluate(`document.documentElement.outerHTML`, &dom))
		_ = chromedp.Run(ctx, actions...)
	}
	hits := readRuntimeDOMHits(ctx)
	trace := runtimeDOMHitSummary(hits)
	reflected := strings.Contains(dom, canary) || len(hits) > 0
	storeDOMReflection(key, reflected, trace)
	return reflected
}

// renderInsertion returns the post-render DOM for one benign injected value.
// CSTI uses it to distinguish a server reflection from client-side evaluation;
// the shared navigation gate keeps the single Chromium tab race-free.
func (b *browserXSSConfirmer) renderInsertion(parent context.Context, ip insertionPoint, auth map[string]string, value string) string {
	if b == nil {
		return ""
	}
	loc := insertionLocation(ip)
	method := strings.ToUpper(strings.TrimSpace(ip.Method))
	if loc == "json" || loc == "multipart" || loc == "xml" || loc == "header" || loc == "cookie" ||
		(method != "" && method != "GET" && method != "POST") {
		return ""
	}
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return ""
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return ""
	}
	ctx, cancel := b.operationContext(parent, tab, 12*time.Second, lease)
	defer cancel()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{ip.URL}, auth)
	defer stopHeaders()
	var dom string
	if method == "POST" {
		parsed, err := url.Parse(ip.URL)
		if err != nil {
			return ""
		}
		origin := parsed.Scheme + "://" + parsed.Host + "/"
		actionJSON, _ := json.Marshal(ip.URL)
		valuesJSON, _ := json.Marshal(browserFormValues(ip, value))
		script := fmt.Sprintf(`(()=>{const a=%s,v=%s,f=document.createElement('form');f.method='POST';f.action=a;for(const [k,vs] of Object.entries(v)){for(const x of vs){const i=document.createElement('input');i.type='hidden';i.name=k;i.value=x;f.appendChild(i)}}document.body.appendChild(f);f.submit()})()`, actionJSON, valuesJSON)
		actions := append(headerActions, chromedp.Navigate(origin), chromedp.Evaluate(script, nil), chromedp.Sleep(900*time.Millisecond), chromedp.Evaluate(`document.documentElement.outerHTML`, &dom))
		_ = chromedp.Run(ctx, actions...)
		return dom
	}
	req, err := buildInjectedRequest(ctx, ip, value, auth)
	if err != nil {
		return ""
	}
	actions := append(headerActions, chromedp.Navigate(req.URL.String()), chromedp.Sleep(900*time.Millisecond), chromedp.Evaluate(`document.documentElement.outerHTML`, &dom))
	_ = chromedp.Run(ctx, actions...)
	return dom
}

func (b *browserXSSConfirmer) renderedDOMURLContains(parent context.Context, rawURL string, headers map[string]string, canary string) bool {
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}
	ctx, cancel := b.operationContext(parent, tab, 12*time.Second, lease)
	defer cancel()
	removeInstrumentation := installRuntimeDOMInstrumentation(ctx, tab, canary)
	defer removeInstrumentation()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{rawURL}, headers)
	defer stopHeaders()
	var dom string
	actions := append(headerActions, chromedp.Navigate(rawURL), chromedp.Sleep(800*time.Millisecond), chromedp.Evaluate(`document.documentElement.outerHTML`, &dom))
	_ = chromedp.Run(ctx, actions...)
	hits := readRuntimeDOMHits(ctx)
	trace := runtimeDOMHitSummary(hits)
	key := "dom-source\x00" + rawURL + "\x00" + authFingerprint(headers)
	reflected := strings.Contains(dom, canary) || len(hits) > 0
	storeDOMReflection(key, reflected, trace)
	// DOM-XSS escalation cares about dangerous sink reach, not textContent or a
	// harmless rendered text node. Plain visibility remains available through the
	// parameter-reflection path.
	return len(hits) > 0
}

// DOMSourceReflects is the source-mode preflight used by the broad DOM-XSS pass.
// A harmless canary costs one navigation for query/path sources and at most four
// fragment shapes for hash routers; only a rendered reflection pays for the full
// execution ladder. Static source→eval leads can bypass this preflight through a
// small fallback budget in VerifyDOMXSSOnPages because eval need not write text.
func (b *browserXSSConfirmer) DOMSourceReflects(parent context.Context, pageURL, mode, param string, auth map[string]string) bool {
	base := strings.SplitN(pageURL, "#", 2)[0]
	switch mode {
	case "query":
		if param == "" {
			param = "rcx"
		}
		ip := insertionPoint{URL: base, Param: param, Method: "GET", Location: "query"}
		return b.DOMReflectsInsertion(parent, ip, auth) && b.RuntimeTrace(ip, auth) != ""
	case "path":
		ip := insertionPoint{URL: base, Param: "path", Method: "GET", Location: param}
		return b.DOMReflectsInsertion(parent, ip, auth) && b.RuntimeTrace(ip, auth) != ""
	case "hash":
		key := "dom-source\x00" + base + "\x00hash\x00" + param + "\x00" + authFingerprint(auth)
		if reflected, ok := cachedDOMReflection(key); ok {
			return reflected
		}
		canary := randNonce()
		placements := []string{}
		if param != "" {
			placements = append(placements, "#"+url.QueryEscape(param)+"="+url.QueryEscape(canary))
		}
		placements = append(placements, "#"+canary, "#/"+canary, "#!/"+canary)
		for _, suffix := range placements {
			if b.renderedDOMURLContains(parent, base+suffix, auth, canary) {
				storeDOMReflection(key, true)
				return true
			}
		}
		storeDOMReflection(key, false)
		return false
	default:
		// window.name/postMessage are only scheduled from static leads and have
		// dedicated faithful-origin runtime drivers; do not synthesize a weaker
		// canary model for them here.
		return true
	}
}

// ConfirmDOMSource proves DOM XSS by placing an EXECUTING payload in a URL source
// (the fragment for mode="hash", or a query param for mode="query") of pageURL and
// observing it actually run in a real browser. This is real proof of DOM XSS — the
// value flows from an attacker-controlled URL source, through the app's JS, into a
// sink, and executes. The returned PoC is the exact nonce + alert('reconner')
// payload observed by the scanner.
func (b *browserXSSConfirmer) ConfirmDOMSource(parent context.Context, pageURL, mode, param string, auth map[string]string) (payload string, ok bool) {
	if b == nil {
		return "", false
	}
	base := strings.SplitN(pageURL, "#", 2)[0]
	for _, tmpl := range xssBrowserPayloads() {
		if parent.Err() != nil {
			return "", false
		}
		nonce := randNonce()
		pl := fmt.Sprintf(tmpl, nonce)
		fired := false
		switch mode {
		case "hash":
			// Cover raw fragments, hash routers and URLSearchParams-over-hash. A
			// single #payload shape systematically missed #/route, #!/route and
			// #name=value consumers even though their source→sink flow was real.
			placements := []string{}
			if param != "" {
				// A fragment parsed via URLSearchParams needs a fully URL-encoded
				// value; minimal query escaping leaves `=`/quotes ambiguous here.
				placements = append(placements, "#"+url.QueryEscape(param)+"="+url.QueryEscape(pl))
			}
			placements = append(placements, "#"+pl, "#/"+pl, "#!/"+pl)
			for _, suffix := range placements {
				if b.fireWithHeaders(parent, base+suffix, auth, nonce) {
					fired = true
					break
				}
			}
		case "query":
			if param == "" {
				param = "rcx"
			}
			fired = b.fireWithHeaders(parent, injectParam(base, param, pl), auth, nonce)
		case "window.name":
			fired = b.fireWindowName(parent, base, pl, auth, nonce)
		case "postMessage":
			fired = b.firePostMessage(parent, base, pl, auth, nonce)
		case "path":
			req, err := buildInjectedRequest(parent, insertionPoint{URL: base, Method: "GET", Location: param}, pl, auth)
			if err == nil {
				fired = b.fireWithHeaders(parent, req.URL.String(), auth, nonce)
			}
		}
		if fired {
			return pl, true
		}
	}
	return "", false
}

func (b *browserXSSConfirmer) fireWindowName(parent context.Context, pageURL, payload string, headers map[string]string, nonce string) bool {
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}
	ctx, cancel := b.operationContext(parent, tab, 15*time.Second, lease)
	defer cancel()
	removeProofObserver := installXSSProofObserver(ctx, tab, nonce)
	defer removeProofObserver()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{pageURL}, headers)
	defer stopHeaders()
	payloadJSON, _ := json.Marshal(payload)
	actions := append(headerActions, chromedp.Navigate("about:blank"), chromedp.Evaluate(`window.name=`+string(payloadJSON), nil), chromedp.Navigate(pageURL))
	if err := chromedp.Run(ctx, actions...); err != nil {
		return false
	}
	return strings.TrimSpace(b.waitForExecution(ctx, nonce)) == nonce
}

// firePostMessage uses an opaque-origin data: iframe as the attacker page. A
// synthetic MessageEvent from the target itself would bypass the browser's origin
// model and could false-confirm guarded code; a real child frame postMessage keeps
// the proof faithful to what an external origin can deliver.
func (b *browserXSSConfirmer) firePostMessage(parent context.Context, pageURL, payload string, headers map[string]string, nonce string) bool {
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}
	ctx, cancel := b.operationContext(parent, tab, 15*time.Second, lease)
	defer cancel()
	removeProofObserver := installXSSProofObserver(ctx, tab, nonce)
	defer removeProofObserver()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{pageURL}, headers)
	defer stopHeaders()
	actions := append(headerActions, chromedp.Navigate(pageURL))
	if err := chromedp.Run(ctx, actions...); err != nil {
		return false
	}
	src := b.scriptLoaderPage() + "/post-message?payload=" + url.QueryEscape(payload)
	srcJSON, _ := json.Marshal(src)
	script := `(()=>{const f=document.createElement('iframe');f.hidden=true;f.src=` + string(srcJSON) + `;document.body.appendChild(f)})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, nil)); err != nil {
		return false
	}
	return strings.TrimSpace(b.waitForExecution(ctx, nonce)) == nonce
}

// fire navigates the single shared tab to url and returns whether the payload's
// JavaScript executed (document.title became nonce). Navigations are serialized on
// navGate because there is only one tab.
func (b *browserXSSConfirmer) fire(parent context.Context, url, nonce string) bool {
	return b.fireWithHeaders(parent, url, nil, nonce)
}

func (b *browserXSSConfirmer) fireWithHeaders(parent context.Context, rawURL string, headers map[string]string, nonce string) bool {
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)

	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}

	ctx, cancel := b.operationContext(parent, tab, 12*time.Second, lease)
	defer cancel()
	removeProofObserver := installXSSProofObserver(ctx, tab, nonce)
	defer removeProofObserver()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{rawURL}, headers)
	defer stopHeaders()
	actions := append(headerActions, chromedp.Navigate(rawURL))
	_ = chromedp.Run(ctx, actions...)
	title := b.waitForExecution(ctx, nonce)
	return strings.TrimSpace(title) == nonce
}

func (b *browserXSSConfirmer) fireScriptResource(parent context.Context, resourceURL string, headers map[string]string, nonce string) bool {
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}
	ctx, cancel := b.operationContext(parent, tab, 15*time.Second, lease)
	defer cancel()
	removeProofObserver := installXSSProofObserver(ctx, tab, nonce)
	defer removeProofObserver()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{resourceURL}, headers)
	defer stopHeaders()
	resourceJSON, _ := json.Marshal(resourceURL)
	loader := `(()=>{const s=document.createElement('script');s.src=` + string(resourceJSON) + `;document.head.appendChild(s)})()`
	loaderURL := b.scriptLoaderPage()
	if loaderURL == "" {
		return false
	}
	actions := append(headerActions, chromedp.Navigate(loaderURL), chromedp.Evaluate(loader, nil))
	if err := chromedp.Run(ctx, actions...); err != nil {
		return false
	}
	return strings.TrimSpace(b.waitForExecution(ctx, nonce)) == nonce
}

func (b *browserXSSConfirmer) fireForm(parent context.Context, action string, values url.Values, headers map[string]string, nonce string) bool {
	gate, lease, acquired := b.acquireNavigation(parent)
	if !acquired {
		return false
	}
	defer b.releaseNavigation(gate, lease)
	tab, ok := b.ensureTab(lease)
	if !ok {
		return false
	}
	ctx, cancel := b.operationContext(parent, tab, 15*time.Second, lease)
	defer cancel()
	removeProofObserver := installXSSProofObserver(ctx, tab, nonce)
	defer removeProofObserver()
	headerActions, stopHeaders := scopedBrowserHeaderSession(ctx, tab, parent, []string{action}, headers)
	defer stopHeaders()
	parsed, err := url.Parse(action)
	if err != nil {
		return false
	}
	origin := parsed.Scheme + "://" + parsed.Host + "/"
	actionJSON, _ := json.Marshal(action)
	valuesJSON, _ := json.Marshal(values)
	script := fmt.Sprintf(`(()=>{const a=%s,v=%s,f=document.createElement('form');f.method='POST';f.action=a;for(const [k,vs] of Object.entries(v)){for(const x of vs){const i=document.createElement('input');i.type='hidden';i.name=k;i.value=x;f.appendChild(i)}}document.body.appendChild(f);f.submit()})()`, actionJSON, valuesJSON)
	actions := append(headerActions, chromedp.Navigate(origin), chromedp.Evaluate(script, nil))
	_ = chromedp.Run(ctx, actions...)
	title := b.waitForExecution(ctx, nonce)
	return strings.TrimSpace(title) == nonce
}

func (b *browserXSSConfirmer) waitForExecution(ctx context.Context, nonce string) string {
	// Poll is a chromedp action and must run through chromedp.Run so the CDP
	// executor is attached to the context. Calling Action.Do(ctx) directly panics
	// in current chromedp (nil cdp.Executor), which previously crashed live XSS
	// scans as soon as a Mac/Linux browser was actually available. The poll also
	// repeats nonce-scoped interactions: this removes the old unconditional 250ms
	// wait for synchronous proofs and still catches controls added later by SPA
	// hydration (the former one-shot trigger missed those).
	proofExpr := xssProofPollExpression(nonce)
	_ = chromedp.Run(ctx, chromedp.Poll(proofExpr, nil,
		chromedp.WithPollingInterval(100*time.Millisecond), chromedp.WithPollingTimeout(1250*time.Millisecond)))
	var proof string
	readProof := `(()=>document.title===` + strconv.Quote(nonce) + `?document.title:(window.` + xssProofResultKey + `||''))()`
	_ = chromedp.Run(ctx, chromedp.Evaluate(readProof, &proof))
	return proof
}

func xssProofPollExpression(nonce string) string {
	quoted := strconv.Quote(nonce)
	return `(()=>{const n=` + quoted + `;if(document.title===n||window.` + xssProofResultKey + `===n)return true;` +
		`for(const e of document.querySelectorAll('*')){for(const a of [...e.attributes]){if(!a.value.includes(n))continue;try{if(a.name==='href'&&a.value.toLowerCase().startsWith('javascript:'))e.click();else if(a.name==='autofocus')e.focus();else if(a.name.startsWith('on')){const t=a.name.slice(2);if(t==='focus')e.focus();else if(t==='click')e.click();else e.dispatchEvent(new Event(t,{bubbles:true}))}}catch(_){}}}` +
		`return document.title===n||window.` + xssProofResultKey + `===n})()`
}
