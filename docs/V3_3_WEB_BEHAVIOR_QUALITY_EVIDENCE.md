# Reconner v3.3 Web behavior quality evidence

Release candidate: v3.3.0.

This is bounded quality and performance evidence for the named local matrix. It
is not an internet-wide detection percentage. Every HTTP endpoint used below is
an in-process Go `httptest` server bound to loopback and authored specifically
for the test. No external application was scanned.

## Detector contracts

### 403 bypass

The first pass runs independent header/path techniques concurrently. A 200 is
not enough: the original URL must produce two materially equivalent 403
controls, the technique must reproduce two materially equivalent 200 responses,
the body must differ from the access wall, and login/auth-wall content is
rejected. Path-normalization results remain candidates because a normalized URL
can legitimately select a different public route.

### Host-header trust

Eight override vectors are isolated rather than combined. A positive vector is
replayed with a second random host. Reconner requires that each value controls a
URL sink in a redirect/response header, parsed HTML attribute or structured body.
Plain diagnostic reflection does not qualify.

### CRLF

Seven encoding/normalization families run in one bounded wave. Any apparent
success is replayed with a different random header name and value. Both response
headers must be observed exactly before the result is confirmed.

### Prototype pollution

GET/query probes retain bracket, dotted, constructor and JSON-value shapes as
candidate discovery. Authenticated JSON request contracts receive structured
`__proto__` and `constructor.prototype` probes with required sibling fields. A
finding requires two independent random properties to appear as top-level JSON
response fields; simple nested echo of the submitted object cannot satisfy it.

### Web cache deception

An authenticated baseline must differ from an anonymous baseline. A random
unrelated path is the SPA/catch-all control. Path-mapping, delimiter, encoded
delimiter, extension and static-prefix normalization cache keys are seeded in
parallel, then fetched anonymously. Promotion requires the same private body and
an explicit cache-hit signal or positive `Age`.

The cache variants follow the discrepancy classes described by
[PortSwigger's web-cache-deception methodology](https://portswigger.net/web-security/web-cache-deception).
Host override coverage follows the distinct override-header and executable-sink
model in the
[HTTP Host header methodology](https://portswigger.net/web-security/host-header).
JSON prototype proof uses the non-destructive property-reflection principle from
[PortSwigger's server-side prototype-pollution research](https://portswigger.net/web-security/prototype-pollution/server-side).

## Named matrix

Positive fixtures (13):

- four 403 techniques: forwarded URI, true client IP, forwarded chain and matrix
  path;
- four host override/sink pairs: content-location, link, refresh and structured
  JSON URL;
- two CRLF decode chains: double and triple decoding;
- authenticated query prototype discovery;
- authenticated JSON prototype top-level dual proof;
- delimiter-based cache deception carrying private JSON.

Negative controls (4):

- bare host reflection without a URL sink;
- cache `HIT-FOR-PASS`, `MISS`, dynamic and zero-age signals;
- an unstable 403 baseline;
- crawl URLs that differ only in query values.

Observed release result: **13/13 positives and 4/4 negative controls passed**,
including three consecutive runs and targeted execution under Go's race detector.

## Performance evidence

Before this change, the five detector families ran sequentially and several
families serialized every negative technique plus its replay. v3.3 overlaps the
independent families, parallelizes bounded first-pass techniques, replays only
positive signals and removes duplicate route/value work.

On the release workstation, the same pre-existing focused detector test command
fell from **2.639s** to **0.920s**, a **2.87x speedup** and **65.1% elapsed-time
reduction**. The synthetic 40ms-per-request gate completed in approximately
0.22s while observing at least eight concurrent requests. These timings are
machine-specific regression evidence, not a promise for arbitrary network
latency or rate limits.

## Reproduction

```bash
go test ./internal/scanner -run '^TestWebBehaviorV33_' -count=3

go test -race ./internal/scanner -run '^TestWebBehaviorV33_' -count=2

go test ./internal/scanner \
  -run 'Test(WebBehaviorV33|CRLF|403|HostHeader|Prototype|CacheDeception)' \
  -count=3
```

The release still requires the repository's complete formatting, module, unit,
race, deterministic detector, migration, frontend, security, amd64 and arm64
container gates on the same commit.
