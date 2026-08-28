package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"time"
)

// In-app tool management. A fresh install (or a locked-down box, or a failed
// `go install` during setup) can leave some external scanners missing — every
// module degrades gracefully without them, but a community user wants a way to
// FIX that without leaving the UI. This exposes, per expected tool: whether it is
// installed, HOW to install it (go / pip / apt / manual), the exact command, and
// a one-click installer for the user-space methods (go install, pip --user) that
// need no root. apt/manual tools return the copy-paste command + a docs link.

type toolInstallMethod string

const (
	methodGo     toolInstallMethod = "go"     // go install <ref>   → user-space, no root
	methodPip    toolInstallMethod = "pip"    // pip install --user <ref>
	methodApt    toolInstallMethod = "apt"    // needs root — shown as a command, not auto-run
	methodManual toolInstallMethod = "manual" // download/build — docs link
)

type toolSpec struct {
	Method toolInstallMethod `json:"method"`
	Ref    string            `json:"ref"`   // go module@version / pip package / apt package
	Doc    string            `json:"doc"`   // upstream docs/releases URL
	Notes  string            `json:"notes"` // extra requirements (e.g. libpcap for naabu)
}

// toolCatalog maps each expected tool to how it is installed. Go tools install
// into the app's tools dir (user-space) and are picked up immediately.
var toolCatalog = map[string]toolSpec{
	// ── ProjectDiscovery + Go tools (one-click, no root) ──
	"subfinder":   {methodGo, "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "https://github.com/projectdiscovery/subfinder", ""},
	"httpx":       {methodGo, "github.com/projectdiscovery/httpx/cmd/httpx@latest", "https://github.com/projectdiscovery/httpx", ""},
	"nuclei":      {methodGo, "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "https://github.com/projectdiscovery/nuclei", ""},
	"katana":      {methodGo, "github.com/projectdiscovery/katana/cmd/katana@latest", "https://github.com/projectdiscovery/katana", ""},
	"naabu":       {methodGo, "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "https://github.com/projectdiscovery/naabu", "Needs libpcap (Debian/Ubuntu: apt install libpcap-dev) and CGO to build SYN scanning."},
	"dnsx":        {methodGo, "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "https://github.com/projectdiscovery/dnsx", ""},
	"alterx":      {methodGo, "github.com/projectdiscovery/alterx/cmd/alterx@latest", "https://github.com/projectdiscovery/alterx", ""},
	"asnmap":      {methodGo, "github.com/projectdiscovery/asnmap/cmd/asnmap@latest", "https://github.com/projectdiscovery/asnmap", ""},
	"shuffledns":  {methodGo, "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", "https://github.com/projectdiscovery/shuffledns", "Also needs massdns on PATH."},
	"uncover":     {methodGo, "github.com/projectdiscovery/uncover/cmd/uncover@latest", "https://github.com/projectdiscovery/uncover", ""},
	"gau":         {methodGo, "github.com/lc/gau/v2/cmd/gau@latest", "https://github.com/lc/gau", ""},
	"waybackurls": {methodGo, "github.com/tomnomnom/waybackurls@latest", "https://github.com/tomnomnom/waybackurls", ""},
	"assetfinder": {methodGo, "github.com/tomnomnom/assetfinder@latest", "https://github.com/tomnomnom/assetfinder", ""},
	"hakrawler":   {methodGo, "github.com/hakluke/hakrawler@latest", "https://github.com/hakluke/hakrawler", ""},
	"dalfox":      {methodGo, "github.com/hahwul/dalfox/v2@latest", "https://github.com/hahwul/dalfox", ""},
	"subzy":       {methodGo, "github.com/PentestPad/subzy@latest", "https://github.com/PentestPad/subzy", ""},
	"gowitness":   {methodGo, "github.com/sensepost/gowitness@latest", "https://github.com/sensepost/gowitness", ""},
	"puredns":     {methodGo, "github.com/d3mondev/puredns/v2@latest", "https://github.com/d3mondev/puredns", "Also needs massdns on PATH."},
	"scilla":      {methodGo, "github.com/edoardottt/scilla/cmd/scilla@latest", "https://github.com/edoardottt/scilla", ""},

	// ── pip (one-click, user-space --user) ──
	"waymore":   {methodPip, "waymore", "https://github.com/xnl-h4ck3r/waymore", ""},
	"uro":       {methodPip, "uro", "https://github.com/s0md3v/uro", ""},
	"dirsearch": {methodPip, "dirsearch", "https://github.com/maurosoria/dirsearch", ""},

	// ── apt (needs root — command shown, not auto-run) ──
	"nmap":    {methodApt, "nmap", "https://nmap.org", ""},
	"hydra":   {methodApt, "hydra", "https://github.com/vanhauser-thc/thc-hydra", "Debian/Ubuntu package is 'hydra'."},
	"sqlmap":  {methodApt, "sqlmap", "https://github.com/sqlmapproject/sqlmap", "Or: pip install --user sqlmap-dev / git clone."},
	"python3": {methodApt, "python3", "https://www.python.org", ""},

	// ── manual (prebuilt binary / distro-specific) ──
	"findomain":   {methodManual, "", "https://github.com/Findomain/Findomain/releases", "Download the prebuilt binary and put it on PATH."},
	"feroxbuster": {methodManual, "", "https://github.com/epi052/feroxbuster#-installation", "apt/brew/cargo or a prebuilt release binary."},
}

// toolCommand returns the shell command a user would run to install the tool
// manually — the same command the one-click installer runs, so it is copy-paste
// reproducible.
func (h *Handler) toolCommand(name string, s toolSpec) string {
	switch s.Method {
	case methodGo:
		return "GOBIN=" + h.cfg.ToolsDir + " go install " + s.Ref
	case methodPip:
		return "pip install --user " + s.Ref
	case methodApt:
		return "sudo apt-get install -y " + s.Ref
	default:
		return ""
	}
}

type toolCatalogEntry struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Method    string `json:"method"`
	Command   string `json:"command"`
	Doc       string `json:"doc"`
	Notes     string `json:"notes"`
	OneClick  bool   `json:"one_click"` // true when the app can install it without root
}

// handleToolCatalog (GET /tools/catalog) returns every expected tool with its
// install status, method, exact command, docs link, and whether one-click
// install is possible on this host.
func (h *Handler) handleToolCatalog(w http.ResponseWriter, r *http.Request) {
	ex := h.sched.GetExecutor()
	goOK := haveOnPath("go")
	pipOK := haveOnPath("pip3") || haveOnPath("pip")

	var out []toolCatalogEntry
	for _, name := range h.sched.ExpectedTools() {
		s, ok := toolCatalog[name]
		if !ok {
			s = toolSpec{Method: methodManual}
		}
		oneClick := (s.Method == methodGo && goOK) || (s.Method == methodPip && pipOK)
		out = append(out, toolCatalogEntry{
			Name:      name,
			Installed: ex.IsToolAvailable(name),
			Method:    string(s.Method),
			Command:   h.toolCommand(name, s),
			Doc:       s.Doc,
			Notes:     s.Notes,
			OneClick:  oneClick,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		// missing first (so the user sees what needs fixing), then by name.
		if out[i].Installed != out[j].Installed {
			return !out[i].Installed
		}
		return out[i].Name < out[j].Name
	})
	h.writeSuccess(w, out)
}

// handleToolInstall (POST /tools/install {"tool":"nuclei"}) installs a single
// tool via its user-space method (go / pip). Root methods (apt) and manual tools
// are NOT auto-run — the response returns the command + docs so the user can run
// it themselves. The tool name is validated against the fixed catalog, so no
// arbitrary command can be injected.
func (h *Handler) handleToolInstall(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tool string `json:"tool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Tool == "" {
		h.writeError(w, http.StatusBadRequest, "missing tool name")
		return
	}
	s, ok := toolCatalog[body.Tool]
	if !ok {
		h.writeError(w, http.StatusBadRequest, "unknown tool: "+body.Tool)
		return
	}
	cmdStr := h.toolCommand(body.Tool, s)

	// Only user-space methods are auto-run.
	if s.Method != methodGo && s.Method != methodPip {
		h.writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"data": map[string]any{
				"installed": false,
				"manual":    true,
				"command":   cmdStr,
				"doc":       s.Doc,
				"notes":     s.Notes,
				"message":   "This tool needs a privileged/manual install — run the command below on the host.",
			},
		})
		return
	}

	if err := os.MkdirAll(h.cfg.ToolsDir, 0o755); err != nil {
		h.writeError(w, http.StatusInternalServerError, "cannot create tools dir: "+err.Error())
		return
	}

	// Generous timeout — a cold `go install` of a big module can take minutes.
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Minute)
	defer cancel()

	var out []byte
	var runErr error
	switch s.Method {
	case methodGo:
		if !haveOnPath("go") {
			h.installUnavailable(w, "go", cmdStr, s)
			return
		}
		c := exec.CommandContext(ctx, "go", "install", s.Ref)
		c.Env = append(os.Environ(),
			"GOBIN="+h.cfg.ToolsDir,
			"GOFLAGS=-buildvcs=false",
		)
		out, runErr = c.CombinedOutput()
	case methodPip:
		pip := "pip3"
		if !haveOnPath("pip3") {
			pip = "pip"
		}
		if !haveOnPath(pip) {
			h.installUnavailable(w, "pip", cmdStr, s)
			return
		}
		c := exec.CommandContext(ctx, pip, "install", "--user", "--upgrade", s.Ref)
		out, runErr = c.CombinedOutput()
	}

	installed := h.sched.GetExecutor().IsToolAvailable(body.Tool)
	if runErr != nil && !installed {
		h.writeJSON(w, http.StatusOK, map[string]any{
			"success": false,
			"data": map[string]any{
				"installed": false,
				"command":   cmdStr,
				"doc":       s.Doc,
				"notes":     s.Notes,
				"output":    tailString(string(out), 4000),
				"message":   "Install failed: " + runErr.Error(),
			},
		})
		return
	}

	h.writeSuccess(w, map[string]any{
		"installed": installed,
		"command":   cmdStr,
		"output":    tailString(string(out), 2000),
		"message":   "Installed " + body.Tool + " successfully.",
	})
}

func (h *Handler) installUnavailable(w http.ResponseWriter, need, cmdStr string, s toolSpec) {
	h.writeJSON(w, http.StatusOK, map[string]any{
		"success": false,
		"data": map[string]any{
			"installed": false,
			"manual":    true,
			"command":   cmdStr,
			"doc":       s.Doc,
			"notes":     s.Notes,
			"message":   need + " is not available on this host — run the command below manually, or use the Docker image (all tools are bundled).",
		},
	})
}

// haveOnPath reports whether a binary is resolvable on PATH.
func haveOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// tailString returns the last n bytes of s (install logs are most useful at the end).
func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
