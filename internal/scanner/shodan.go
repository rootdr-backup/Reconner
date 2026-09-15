package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// ShodanScanner pulls passive host intel (open ports, service banners, extra
// hostnames) from Shodan for the target's resolved IPs. Gated on an API key —
// no key → explicitly blocked. Purely passive: it never touches the target, only
// Shodan's index, so it's safe to run against any in-scope host.
type ShodanScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewShodanScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *ShodanScanner {
	return &ShodanScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var shodanClient = &http.Client{Timeout: 20 * time.Second}
var shodanPace = time.Second

type shodanHostResp struct {
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Data      []struct {
		Port    int    `json:"port"`
		Product string `json:"product"`
	} `json:"data"`
}

func (s *ShodanScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	key := strings.TrimSpace(s.cfg.ShodanAPIKey)
	if key == "" {
		logFn("info", "shodan", "No Shodan API key configured — phase blocked")
		return BlockedPhase("Shodan API key is not configured")
	}

	ips := s.gatherIPs(ctx, targetID)
	if len(ips) == 0 {
		logFn("info", "shodan", "No resolved IPs to query — phase blocked")
		return BlockedPhase("no resolved target IPs are available for Shodan lookup")
	}
	logFn("info", "shodan", fmt.Sprintf("Querying Shodan for %d hosts...", len(ips)))

	ports := 0
	failedQueries := 0
	for ip := range ips {
		if ctx.Err() != nil {
			break
		}
		resp, err := s.queryHost(ctx, key, ip)
		if err != nil {
			failedQueries++
			logFn("warn", "shodan", fmt.Sprintf("Shodan query failed for %s: %v", ip, err))
			continue
		}
		if resp == nil {
			continue
		}
		productByPort := map[int]string{}
		for _, d := range resp.Data {
			productByPort[d.Port] = d.Product
		}
		host := ips[ip] // the subdomain we resolved this IP from
		for _, p := range resp.Ports {
			svc := productByPort[p]
			if svc == "" {
				svc = commonServicePorts[p]
			}
			if s.storeShodanPort(targetID, host, ip, p, svc, logFn) {
				ports++
			}
		}
		// polite pacing — Shodan rate-limits at ~1 req/s on most plans
		select {
		case <-time.After(shodanPace):
		case <-ctx.Done():
		}
	}
	if failedQueries > 0 {
		return BlockedPhase(fmt.Sprintf("%d of %d Shodan host queries failed", failedQueries, len(ips)))
	}
	logFn("info", "shodan", fmt.Sprintf("Shodan intel complete: %d ports recorded", ports))
	return nil
}

// gatherIPs returns a map of IP → representative hostname for resolved subdomains.
func (s *ShodanScanner) gatherIPs(ctx context.Context, targetID string) map[string]string {
	out := map[string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT subdomain, ip FROM subdomains WHERE target_id=? AND ip != ''`, targetID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var sub, ip string
		_ = rows.Scan(&sub, &ip)
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, ok := out[ip]; !ok {
			out[ip] = sub
		}
	}
	return out
}

func (s *ShodanScanner) queryHost(ctx context.Context, key, ip string) (*shodanHostResp, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, key)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := shodanClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil // no info for this IP — a valid negative result
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out shodanHostResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

func (s *ShodanScanner) storeShodanPort(targetID, host, ip string, port int, svc string, logFn LogFunc) bool {
	res, err := s.db.Exec(`
		INSERT INTO open_ports (id, target_id, host, ip, port, service, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, host, port) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, ip=excluded.ip`,
		uuid.New().String(), targetID, host, ip, port, svc)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logFn("info", "shodan", fmt.Sprintf("%s (%s):%d %s", host, ip, port, svc))
		return true
	}
	return false
}
