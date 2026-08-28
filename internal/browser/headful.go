package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Desktop-mode interactive capture. Only meaningful when Reconner runs where the
// researcher can SEE the browser (their laptop / a desktop with a display). On a
// headless server there is no display, so StartSession returns a clear error and
// the researcher uses import mode instead.

// Session is a live, researcher-driven browser used only to authenticate.
type Session struct {
	ID        string
	Origin    string
	cancel    context.CancelFunc
	allocDone context.CancelFunc
	ctx       context.Context
	createdAt time.Time
}

// Manager keeps interactive login sessions alive between HTTP calls.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewManager() *Manager { return &Manager{sessions: map[string]*Session{}} }

// displayAvailable reports whether a headful browser can actually be shown.
func displayAvailable() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

// StartSession launches a HEADFUL Chromium at origin so the researcher can log
// in manually. Returns an error (not a crash) when no display is available.
func (m *Manager) StartSession(id, origin, chromePath string) (*Session, error) {
	if !displayAvailable() {
		return nil, fmt.Errorf("no display on this host — use Import mode: export your browser's storageState and import it")
	}
	if chromePath == "" {
		if p, err := exec.LookPath("chromium"); err == nil {
			chromePath = p
		} else if p, err := exec.LookPath("google-chrome"); err == nil {
			chromePath = p
		} else {
			return nil, fmt.Errorf("no chromium/chrome binary found")
		}
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", false), // researcher must SEE and drive it
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(ctx, chromedp.Navigate(origin)); err != nil {
		cancel()
		allocCancel()
		return nil, fmt.Errorf("failed to open browser: %w", err)
	}
	s := &Session{ID: id, Origin: origin, cancel: cancel, allocDone: allocCancel, ctx: ctx, createdAt: time.Now()}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// Capture extracts the authenticated context (cookies + localStorage + UA) from
// a live session after the researcher finished logging in.
func (m *Manager) Capture(id string) (CapturedContext, error) {
	m.mu.Lock()
	s := m.sessions[id]
	m.mu.Unlock()
	if s == nil {
		return CapturedContext{}, fmt.Errorf("no such session")
	}
	return captureFrom(s.ctx, s.Origin)
}

// Close ends a session and frees the browser.
func (m *Manager) Close(id string) {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if s != nil {
		s.cancel()
		s.allocDone()
	}
}
