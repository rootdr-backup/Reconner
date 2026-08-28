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
// no key → skipped cleanly. Purely passive: it never touches the target, only
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
		logFn("info", "shodan", "No Shodan API key configured — skipping")
		return nil
	}

	ips := s.gatherIPs(ctx, targetID)
	if len(ips) == 0 {
		logFn("info", "shodan", "No resolved IPs to query")
		return nil
	}
	logFn("info", "shodan", fmt.Sprintf("Querying Shodan for %d hosts...", len(ips)))

	ports := 0
	for ip := range ips {
		if ctx.Err() != nil {
			break
		}
		resp := s.queryHost(ctx, key, ip, logFn)
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
		case <-time.After(time.Second):
		case <-ctx.Done():
		}
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

func (s *ShodanScanner) queryHost(ctx context.Context, key, ip string, logFn LogFunc) *shodanHostResp {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, key)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := shodanClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil // no info for this IP — normal
	}
	if resp.StatusCode != 200 {
		logFn("info", "shodan", fmt.Sprintf("Shodan returned %d for %s", resp.StatusCode, ip))
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out shodanHostResp
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	return &out
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
