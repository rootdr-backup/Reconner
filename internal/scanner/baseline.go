package scanner

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

// Adaptive per-endpoint baselining.
//
// Every differential injection check (boolean SQLi, NoSQL $ne/$eq, length-diff
// heuristics) has to answer one question: "is THIS response-size change caused by
// my payload, or is it just how much this page normally wobbles?" The old code
// answered it with FIXED byte constants (48 / 200). Those constants are wrong for
// almost every real page: a marketing homepage with rotating ads, CSRF tokens,
// view counters and timestamps legitimately varies by hundreds of bytes between
// two IDENTICAL requests (so a fixed 200-byte threshold false-positives), while a
// static JSON API varies by zero (so the same threshold is needlessly deaf to a
// small but real signal).
//
// The fix is to MEASURE each endpoint's own noise floor once — send the same
// benign value a few times, see how much the body size swings on its own — and
// then scale the "is this difference meaningful?" threshold off that measured
// wobble instead of a global guess. This is the single highest-leverage
// false-positive reduction across all the differential detectors, and it doubles
// as a WAF gate: if the benign baseline itself comes back as a block/challenge
// page, the endpoint can't be differentially tested at all.

// volProfile is an endpoint's measured response-size volatility (its "noise
// floor") plus baseline size and latency. valid is false when the endpoint could
// not be sampled; blocked is true when a security intermediary answered the
// benign baseline with a block/challenge page.
type volProfile struct {
	valid   bool
	blocked bool
	baseLen int           // median benign body length
	noise   int           // worst-case byte swing across identical benign requests
	slow    time.Duration // median benign round-trip
}

// volCache memoises a profile per (method, host, path, param, benign-value) so
// repeated differential checks against the same endpoint in one scan don't each
// pay for the sampling requests. Entries EXPIRE (volTTL): the process is
// long-lived and the monitor re-scans the same endpoints every ~12h, so a
// profile captured during a transient WAF challenge (blocked=true) must not
// suppress differential testing forever — a re-scan hours later re-measures.
var volCache sync.Map

type volEntry struct {
	p  volProfile
	at time.Time
}

// volTTL is long enough to dedupe sampling within a single scan (minutes) yet
// short enough that a later scan of the same target gets a fresh measurement.
const volTTL = 10 * time.Minute

func volKey(ip insertionPoint, benign string) string {
	host, path := ip.URL, ""
	if u, err := url.Parse(ip.URL); err == nil {
		host, path = u.Host, u.Path
	}
	return ip.Method + "\x00" + host + "\x00" + path + "\x00" + ip.Param + "\x00" + benign
}

// measureVolatility samples the endpoint's benign response `volSamples` times and
// records its size volatility, WAF-block state and latency. Cached per endpoint.
// The benign value should be the SAME neutral value the calling detector uses for
// its own baseline (e.g. "1"), so the profile's baseLen is directly comparable to
// the detector's baseline response.
const volSamples = 3

func measureVolatility(ctx context.Context, client *http.Client, ip insertionPoint, auth map[string]string, benign string) volProfile {
	key := volKey(ip, benign)
	if v, ok := volCache.Load(key); ok {
		if e := v.(volEntry); time.Since(e.at) < volTTL {
			return e.p
		}
	}

	var lens []int
	var durs []time.Duration
	blocked := false
	ok := 0
	for i := 0; i < volSamples; i++ {
		if ctx.Err() != nil {
			break
		}
		body, status, d := sendInjectedFull(ctx, client, ip, benign, auth)
		if status == 0 && body == "" {
			continue // request failed — don't let it distort the profile
		}
		ok++
		if looksLikeWAFBlock(status, body) {
			blocked = true
		}
		lens = append(lens, len(body))
		durs = append(durs, d)
	}

	p := volProfile{}
	if ok == 0 {
		volCache.Store(key, volEntry{p, time.Now()}) // valid=false
		return p
	}
	p.valid = true
	p.blocked = blocked
	p.baseLen = medianInts(lens)
	p.noise = intSwing(lens)
	p.slow = medianDurs(durs)
	volCache.Store(key, volEntry{p, time.Now()})
	return p
}

// sigDiff returns the byte delta a differential response-size change must EXCEED
// to be considered payload-driven for this endpoint: never below `floor`, and
// never below a comfortable multiple of the endpoint's own measured noise. On an
// unmeasured/invalid profile it degrades to the old fixed floor.
func (v volProfile) sigDiff(floor int) int {
	if !v.valid {
		return floor
	}
	t := v.noise*3 + 96 // clear 3× the observed wobble plus a small constant
	if t < floor {
		return floor
	}
	return t
}

// matchesBaseline reports whether a response length is indistinguishable from the
// endpoint's baseline given its own noise — the "TRUE condition looks like the
// normal page" test, adaptive instead of a fixed ±48.
func (v volProfile) matchesBaseline(l int) bool {
	if !v.valid {
		return abs(l-v.baseLen) <= 48
	}
	return abs(l-v.baseLen) <= v.noise+48
}

// medianInts returns the median of a non-empty int slice (0 if empty).
func medianInts(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[len(s)/2]
}

// intSwing returns max-min of an int slice — the worst-case swing observed.
func intSwing(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	mn, mx := xs[0], xs[0]
	for _, x := range xs[1:] {
		if x < mn {
			mn = x
		}
		if x > mx {
			mx = x
		}
	}
	return mx - mn
}

// medianDurs returns the median of a non-empty duration slice (0 if empty).
func medianDurs(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}
