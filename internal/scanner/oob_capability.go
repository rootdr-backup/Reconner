package scanner

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

// oobCapability is the pure out-of-band INFRASTRUCTURE shared by every blind
// detector. It resolves the configured callback endpoints, registers a probe
// token per (target,url,param,kind) in oob_probes, and fires that ONE class's
// payloads. It emits NO vulnerability findings of its own — when the target later
// calls back to /oob/<token>, the API layer (RecordOOBHit) attributes the hit to
// the registering probe's KIND, so the detector that planted the probe owns the
// finding class it proves.
//
// This is what lets each blind detector (SSRF, XXE, CMDi, …) perform its own
// out-of-band confirmation WITHOUT a multi-class OAST module that would plant
// probes for — and therefore emit findings of — unrelated vulnerability classes.
type oobCapability struct {
	callbackBase string // normalized http(s) origin used for /oob/<token>
	callbackHost string // host[:port] of the public callback (for http payloads)
	oobHost      string // bare host for raw JNDI/LDAP listeners
	rawPort      int
}

// newOOBCapability resolves the OOB endpoints from config. ok=false when no
// callback URL is configured, in which case blind confirmation is unavailable and
// callers skip it (no error, no finding).
func newOOBCapability(cfg *config.Config) (oobCapability, bool) {
	if cfg == nil {
		return oobCapability{}, false
	}
	raw := strings.TrimSpace(cfg.BlindXSSCallbackURL)
	if raw == "" {
		return oobCapability{}, false
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return oobCapability{}, false
	}
	rawPort := cfg.OOBRawPort
	if rawPort <= 0 {
		rawPort = 1389
	}
	return oobCapability{
		callbackBase: strings.ToLower(u.Scheme) + "://" + u.Host,
		callbackHost: u.Host,
		oobHost:      u.Hostname(),
		rawPort:      rawPort,
	}, true
}

func (o oobCapability) callbackURL(token string) string {
	return strings.TrimRight(o.callbackBase, "/") + "/oob/" + token
}

// plantClass registers one probe of `kind` for each insertion point matching
// `prone` (nil = every point), then concurrently fires that class's payloads,
// built from each probe's own /oob/<token> callback URL. Returns the number of
// probes planted. Fire-and-forget: any execution is reported asynchronously via
// the callback and correlated to `kind` by RecordOOBHit.
func (o oobCapability) plantClass(
	ctx context.Context,
	db *database.DB,
	targetID string,
	points []insertionPoint,
	auth map[string]string,
	kind string,
	prone func(insertionPoint) bool,
	payloadsFor func(ip insertionPoint, cb string) []string,
) int {
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	planted := 0
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		if prone != nil && !prone(ip) {
			continue
		}
		token := registerOOBProbe(db, targetID, ip.URL, ip.Param, kind, "param:"+ip.Param)
		cb := o.callbackURL(token)
		planted++
		for _, v := range payloadsFor(ip, cb) {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip insertionPoint, v string) {
				defer wg.Done()
				defer func() { <-sem }()
				sendInjected(ctx, oastClient, ip, v, auth)
			}(ip, v)
		}
	}
	wg.Wait()
	return planted
}
