package models

import (
	"encoding/json"
	"time"
)

type Target struct {
	ID                   string     `json:"id" db:"id"`
	Domain               string     `json:"domain" db:"domain"`
	Name                 string     `json:"name" db:"name"` // user-supplied friendly name (falls back to domain when empty)
	Kind                 string     `json:"kind" db:"kind"`
	Description          string     `json:"description" db:"description"`
	Tags                 []string   `json:"tags"`
	Priority             string     `json:"priority" db:"priority"`
	Notes                string     `json:"notes" db:"notes"`
	ExcludeScope         string     `json:"exclude_scope" db:"exclude_scope"`
	Status               string     `json:"status" db:"status"`
	ScanStatus           string     `json:"scan_status" db:"scan_status"`
	EnabledModules       []string   `json:"enabled_modules"`
	LastScanAt           *time.Time `json:"last_scan_at" db:"last_scan_at"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	SubdomainCount       int        `json:"subdomain_count" db:"subdomain_count"`
	AliveHostCount       int        `json:"alive_host_count" db:"alive_host_count"`
	FindingCount         int        `json:"finding_count" db:"finding_count"`
	MonitorEnabled       bool       `json:"monitor_enabled" db:"monitor_enabled"`
	MonitorIntervalHours int        `json:"monitor_interval_hours" db:"monitor_interval_hours"`
	MonitorLastRun       *time.Time `json:"monitor_last_run" db:"monitor_last_run"`
}

// Asset is one individually-scannable entry of a target (a domain, IP, CIDR, or
// a mix of them). Named, add/removable, and scanned on its own.
type Asset struct {
	ID             string    `json:"id"`
	TargetID       string    `json:"target_id"`
	Name           string    `json:"name"`
	Value          string    `json:"value"`
	Kind           string    `json:"kind"`       // web | network | mixed
	AssetType      string    `json:"asset_type"` // domain | url | js | wildcard | cidr | ip | api | other
	Source         string    `json:"source"`
	SourceID       string    `json:"source_id"`
	ApprovalStatus string    `json:"approval_status"` // approved | pending | suspended
	MonitorEnabled bool      `json:"monitor_enabled"`
	Metadata       string    `json:"metadata"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Subdomain struct {
	ID             string   `json:"id"`
	TargetID       string   `json:"target_id"`
	Subdomain      string   `json:"subdomain"`
	IP             string   `json:"ip"`
	IsAlive        bool     `json:"is_alive"`
	StatusCode     int      `json:"status_code"`
	PageTitle      string   `json:"page_title"`
	HasHTTPS       bool     `json:"has_https"`
	HasHTTP        bool     `json:"has_http"`
	ResponseTimeMs int      `json:"response_time_ms"`
	Technologies   []string `json:"technologies"`
	Server         string   `json:"server"`
	Framework      string   `json:"framework"`
	CDN            string   `json:"cdn"`
	WAF            string   `json:"waf"`
	// Source: "dns" (DNS enumeration) or "vhost" (found by virtual-host scan).
	Source    string    `json:"source"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

type HTTPService struct {
	ID             string            `json:"id"`
	TargetID       string            `json:"target_id"`
	SubdomainID    string            `json:"subdomain_id"`
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Title          string            `json:"title"`
	Server         string            `json:"server"`
	ContentType    string            `json:"content_type"`
	ContentLength  int               `json:"content_length"`
	RedirectURL    string            `json:"redirect_url"`
	Technologies   []string          `json:"technologies"`
	Headers        map[string]string `json:"headers"`
	FaviconHash    string            `json:"favicon_hash"`
	ResponseTimeMs int               `json:"response_time_ms"`
	ScreenshotID   string            `json:"screenshot_id"`
	WAF            string            `json:"waf"`
	CMS            string            `json:"cms"`
	LastSeen       time.Time         `json:"last_seen"`
	CreatedAt      time.Time         `json:"created_at"`
}

type JSFile struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	URL       string    `json:"url"`
	Size      int       `json:"size"`
	Hash      string    `json:"hash"`
	Analyzed  bool      `json:"analyzed"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

type JSFinding struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	JSFileID  string    `json:"js_file_id"`
	JSFileURL string    `json:"js_file_url"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Context   string    `json:"context"`
	Severity  string    `json:"severity"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

type Parameter struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"target_id"`
	URL         string    `json:"url"`
	Parameter   string    `json:"parameter"`
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	IsReflected bool      `json:"is_reflected"`
	CreatedAt   time.Time `json:"created_at"`
}

type DirectoryFinding struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	URL           string    `json:"url"`
	StatusCode    int       `json:"status_code"`
	ContentLength int       `json:"content_length"`
	RedirectURL   string    `json:"redirect_url"`
	ContentType   string    `json:"content_type"`
	CreatedAt     time.Time `json:"created_at"`
}

type BackupFinding struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	URL           string    `json:"url"`
	StatusCode    int       `json:"status_code"`
	ContentLength int       `json:"content_length"`
	FileType      string    `json:"file_type"`
	BackupType    string    `json:"backup_type"`
	CreatedAt     time.Time `json:"created_at"`
}

type OpenRedirectFinding struct {
	ID         string    `json:"id"`
	TargetID   string    `json:"target_id"`
	URL        string    `json:"url"`
	RedirectTo string    `json:"redirect_to"`
	Parameter  string    `json:"parameter"`
	Verified   bool      `json:"verified"`
	CreatedAt  time.Time `json:"created_at"`
}

type NucleiFinding struct {
	ID           string            `json:"id"`
	TargetID     string            `json:"target_id"`
	TemplateID   string            `json:"template_id"`
	TemplateName string            `json:"template_name"`
	Severity     string            `json:"severity"`
	MatchedURL   string            `json:"matched_url"`
	Description  string            `json:"description"`
	Tags         []string          `json:"tags"`
	Meta         map[string]string `json:"meta"`
	// PoC evidence — populated only for medium+ severity (see nuclei.go).
	CurlCommand string    `json:"curl_command"`
	Request     string    `json:"request"`
	Response    string    `json:"response"`
	CreatedAt   time.Time `json:"created_at"`
	// AffectedCount is how many distinct URLs this same template matched — the
	// list view collapses one template's many near-identical hits into a single
	// row and reports the total here (1 unless the template fired on several URLs).
	AffectedCount int `json:"affected_count"`
}

type VulnFinding struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	URL       string    `json:"url"`
	Parameter string    `json:"parameter"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
	CreatedAt time.Time `json:"created_at"`
}

type Task struct {
	ID            string `json:"id"`
	TargetID      string `json:"target_id"`
	Name          string `json:"name"` // user-supplied scan name (falls back to target domain when empty)
	Type          string `json:"type"`
	Status        string `json:"status"`
	Priority      int    `json:"priority"`
	Progress      int    `json:"progress"`
	Total         int    `json:"total"`
	CurrentModule string `json:"current_module"`
	// EtaSeconds / ModuleEtaSeconds: live estimate of seconds remaining for the
	// whole scan and the current module (0 when not running / unknown).
	EtaSeconds       int      `json:"eta_seconds"`
	ModuleEtaSeconds int      `json:"module_eta_seconds"`
	Modules          []string `json:"modules"`
	// CompletedModules is the subset of Modules that finished successfully —
	// what a Resume (see scheduler.ResumeTask) will SKIP on the next attempt.
	CompletedModules []string   `json:"completed_modules"`
	Error            string     `json:"error"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	TargetDomain     string     `json:"target_domain,omitempty"`
}

type TaskLog struct {
	ID        int64          `json:"id"`
	TaskID    string         `json:"task_id"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Module    string         `json:"module"`
	Data      map[string]any `json:"data"`
	CreatedAt time.Time      `json:"created_at"`
}

type Screenshot struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	URL           string    `json:"url"`
	FilePath      string    `json:"file_path"`
	ThumbnailPath string    `json:"thumbnail_path"`
	Width         int       `json:"width"`
	Height        int       `json:"height"`
	CreatedAt     time.Time `json:"created_at"`
}

type DashboardStats struct {
	Targets              int `json:"targets"`
	AliveHosts           int `json:"alive_hosts"`
	Subdomains           int `json:"subdomains"`
	HTTPServices         int `json:"http_services"`
	JSFiles              int `json:"js_files"`
	Parameters           int `json:"parameters"`
	ReflectedParameters  int `json:"reflected_parameters"`
	DirectoryFindings    int `json:"directory_findings"`
	BackupFindings       int `json:"backup_findings"`
	OpenRedirectFindings int `json:"open_redirect_findings"`
	NucleiFindings       int `json:"nuclei_findings"`
	VulnFindings         int `json:"vuln_findings"`
	RunningTasks         int `json:"running_tasks"`
	FinishedTasks        int `json:"finished_tasks"`
	FailedTasks          int `json:"failed_tasks"`
	PendingTasks         int `json:"pending_tasks"`
}

// JSON serialization helpers

func StringSliceToJSON(s []string) string {
	if s == nil {
		return "[]"
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func JSONToStringSlice(s string) []string {
	var result []string
	if s == "" || s == "null" {
		return []string{}
	}
	_ = json.Unmarshal([]byte(s), &result)
	if result == nil {
		return []string{}
	}
	return result
}

func MapToJSON(m map[string]string) string {
	if m == nil {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func JSONToMap(s string) map[string]string {
	result := make(map[string]string)
	if s == "" || s == "null" {
		return result
	}
	_ = json.Unmarshal([]byte(s), &result)
	return result
}

func AnyMapToJSON(m map[string]any) string {
	if m == nil {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func JSONToAnyMap(s string) map[string]any {
	result := make(map[string]any)
	if s == "" || s == "null" {
		return result
	}
	_ = json.Unmarshal([]byte(s), &result)
	return result
}
