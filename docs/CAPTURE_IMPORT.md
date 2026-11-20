# Capture import

Reconner ingests researcher-observed HTTP traffic through a single canonical
exchange model, so a finding discovered while you were logged in can be
analyzed, replayed and reviewed without Reconner having to rediscover it.
Importing is always **passive**: parsing and preview never send a request.

Supported upload formats (Guided Analyze picks the format from the file):

| Source | Format | Typical producer |
|---|---|---|
| `burp_xml` | Burp Suite "Save items" XML (plain or base64 messages) | Burp Suite |
| `reconner_json` | Reconner capture JSON (`reconner-capture/v1` envelope) | Chrome DevTools collector |
| `har` | HAR 1.1 / 1.2 export | DevTools "Save all as HAR", Charles, Fiddler, mitmproxy |

## Limits and safety

- 32 MiB per upload, 8 MiB per request or response body, 5,000 entries.
- Malformed, oversized or hostile files are rejected whole; nothing is
  partially imported.
- Imported HTML, JavaScript and archive contents are never executed.
- Cookies, bearer tokens and API keys are redacted from previews, logs and
  ordinary API responses; secrets never appear in the UI.
- Out-of-scope hosts, ports, schemes and path-boundary violations are rejected
  at preview time, before anything is persisted.
- Duplicate exchanges are detected deterministically (volatile parameters like
  CSRF tokens are masked; ordinary object IDs are not, so traffic from two
  different owned objects is never collapsed before authorization analysis).

## Sanitized vs sensitive HAR exports

A **sensitive** HAR export contains full request and response bodies. A
**sanitized** export is one where the exporting tool (or your data-loss policy)
stripped bodies — DevTools does this automatically for some response types,
and many proxies offer a "sanitize" toggle that removes bodies, cookies and
headers. Both import fine: sanitized entries simply carry empty bodies and
still contribute routes, parameters, methods and status codes to the corpus.

Two consequences worth knowing:

1. **A sanitized HAR is not an authenticated corpus.** Without bodies and
   headers, authorization analysis cannot conclude anything about access
   control — those entries help map the surface, not prove a bug.
2. **Missing authentication data is not anonymous traffic.** An entry whose
   request carried a session cookie (visible in headers) is still
   authenticated traffic even if the body was stripped; Reconner keeps that
   distinction when attributing exchanges to identities.

Export a sensitive HAR only from tools you control, import it over the same
trust boundary you use for the rest of your Reconner data, and prefer the
per-identity labels so the corpus stays attributable.

## API

`POST /api/targets/{id}/captures/preview` and `POST /api/targets/{id}/captures`
accept multipart uploads with a `file` field and a `source` field
(`burp_xml` | `reconner_json` | `har`). The response reports counts for
accepted, rejected and redacted entries.
