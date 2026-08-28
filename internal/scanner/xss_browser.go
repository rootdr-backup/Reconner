package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
// Detection had to be title-based rather than alert()-dialog-based: chromedp only
// reliably delivers Page.javascriptDialogOpening on the FIRST navigation of a
// fresh browser, so a dialog design forces a browser-per-navigation (the leak).
// Reading document.title after each navigation has no such limitation and lets one
// tab serve the whole scan.
//
// Best-effort: if no Chromium/Chrome binary is present the confirmer disables
// itself and callers fall back to the browserless verifier, so a scan never fails
// for lack of a browser.
type browserXSSConfirmer struct {
	chromePath string
	dataDir    string // explicit user-data-dir we own and delete

	mu          sync.Mutex
	alloc       context.Context
	allocCancel context.CancelFunc
	tab         context.Context // the single reused tab
	tabCancel   context.CancelFunc

	// one navigation at a time: the single tab cannot be driven concurrently.
	navGate chan struct{}
}

var (
	xssBrowserOnce sync.Once
	xssBrowserInst *browserXSSConfirmer
)

const xssProfilePrefix = "reconner-xss-"

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
		dir := filepath.Join(os.TempDir(), xssProfilePrefix+strconv.Itoa(os.Getpid()))
		xssBrowserInst = &browserXSSConfirmer{
			chromePath: p,
			dataDir:    dir,
			navGate:    make(chan struct{}, 1),
		}
	})
	return xssBrowserInst
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
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, name := range []string{
		"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "headless-shell",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	// Common absolute locations (containers / Playwright bundles).
	for _, p := range []string{
		"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
		"/snap/bin/chromium", "/opt/google/chrome/chrome",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ensureTab lazily starts the single shared browser + tab, rebuilding if it died.
func (b *browserXSSConfirmer) ensureTab() (context.Context, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tab != nil && b.tab.Err() == nil {
		return b.tab, true
	}
	if b.tabCancel != nil {
		b.tabCancel()
		b.tab, b.tabCancel = nil, nil
	}
	if b.alloc == nil || b.alloc.Err() != nil {
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
		)
		b.alloc, b.allocCancel = chromedp.NewExecAllocator(context.Background(), opts...)
	}

	// Silence chromedp's CDP event logger: a newer Chromium emits enum values (e.g.
	// network IPAddressSpace "Loopback") that this cdproto version can't unmarshal,
	// which is harmless but would otherwise spam scan logs with ERROR lines.
	noop := func(string, ...interface{}) {}
	tabCtx, tabCancel := chromedp.NewContext(b.alloc,
		chromedp.WithErrorf(noop), chromedp.WithLogf(noop))

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
	b.tab, b.tabCancel = tabCtx, tabCancel
	return b.tab, true
}

// Close tears down the browser/allocator and removes the profile dir. Idempotent.
func (b *browserXSSConfirmer) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tabCancel != nil {
		b.tabCancel()
		b.tab, b.tabCancel = nil, nil
	}
	if b.allocCancel != nil {
		b.allocCancel()
		b.alloc, b.allocCancel = nil, nil
	}
	if b.dataDir != "" {
		_ = os.RemoveAll(b.dataDir)
	}
}

// xssBrowserPayloads are context-spanning payloads whose executed JavaScript sets
// document.title to the nonce (%s). Reading that nonce back from document.title is
// unambiguous execution proof across HTML-text, tag-attribute, and JS-string
// contexts. Kept small so a candidate costs only a handful of navigations.
func xssBrowserPayloads() []string {
	return []string{
		`"><img src=x onerror="document.title='%s'">`,
		`"><svg onload="document.title='%s'">`,
		`'><img src=x onerror="document.title='%s'">`,
		`</script><script>document.title='%s'</script>`,
		`';document.title='%s';//`,
		`"><script>document.title='%s'</script>`,
		`<img src=x onerror="document.title='%s'">`,
	}
}

func randNonce() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "RCNX" + hex.EncodeToString(b[:])
}

// Confirm loads rawURL with each payload injected into param and reports the first
// payload that actually executes in the browser. The returned payload is the
// ALERT-equivalent of the winning vector (document.title→alert(document.domain))
// so the report's PoC actually POPS for a human, while detection stays title-based
// (chromedp cannot reliably observe alert dialogs). ok=false means no execution was
// observed (not vulnerable, or safely encoded/escaped by the app).
func (b *browserXSSConfirmer) Confirm(parent context.Context, rawURL, param string) (payload string, ok bool) {
	if b == nil {
		return "", false
	}
	for _, tmpl := range xssBrowserPayloads() {
		if parent.Err() != nil {
			return "", false
		}
		nonce := randNonce()
		pl := fmt.Sprintf(tmpl, nonce)
		u := injectParam(rawURL, param, pl)
		if b.fire(parent, u, nonce) {
			// same vector, but pop alert(document.domain) for the human PoC.
			return strings.ReplaceAll(tmpl, `document.title='%s'`, `alert(document.domain)`), true
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
	if b == nil {
		return false
	}
	canary := randNonce()
	u := injectParam(rawURL, param, canary)
	select {
	case b.navGate <- struct{}{}:
		defer func() { <-b.navGate }()
	case <-parent.Done():
		return false
	}
	tab, ok := b.ensureTab()
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(tab, 12*time.Second)
	defer cancel()
	var dom string
	_ = chromedp.Run(ctx,
		chromedp.Navigate(u),
		chromedp.Sleep(800*time.Millisecond),
		chromedp.Evaluate(`document.documentElement.outerHTML`, &dom),
	)
	return strings.Contains(dom, canary)
}

// ConfirmDOMSource proves DOM XSS by placing an EXECUTING payload in a URL source
// (the fragment for mode="hash", or a query param for mode="query") of pageURL and
// observing it actually run in a real browser. This is real proof of DOM XSS — the
// value flows from an attacker-controlled URL source, through the app's JS, into a
// sink, and executes. Returns the alert-equivalent payload for the report PoC.
func (b *browserXSSConfirmer) ConfirmDOMSource(parent context.Context, pageURL, mode string) (payload string, ok bool) {
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
		var u string
		if mode == "hash" {
			u = base + "#" + pl
		} else {
			u = injectParam(base, "rcx", pl)
		}
		if b.fire(parent, u, nonce) {
			return strings.ReplaceAll(tmpl, `document.title='%s'`, `alert(document.domain)`), true
		}
	}
	return "", false
}

// fire navigates the single shared tab to url and returns whether the payload's
// JavaScript executed (document.title became nonce). Navigations are serialized on
// navGate because there is only one tab.
func (b *browserXSSConfirmer) fire(parent context.Context, url, nonce string) bool {
	select {
	case b.navGate <- struct{}{}:
		defer func() { <-b.navGate }()
	case <-parent.Done():
		return false
	}

	tab, ok := b.ensureTab()
	if !ok {
		return false
	}

	ctx, cancel := context.WithTimeout(tab, 12*time.Second)
	defer cancel()

	var title string
	// Navigate, give post-load handlers (onerror/onload, hydration) time to run,
	// then read the title. Errors are ignored on purpose — a partial load can still
	// have executed the payload, and Evaluate then reports the proof.
	_ = chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(1100*time.Millisecond),
		chromedp.Evaluate(`document.title`, &title),
	)
	return strings.TrimSpace(title) == nonce
}
