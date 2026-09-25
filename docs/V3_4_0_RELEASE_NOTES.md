# Reconner v3.4.0 (draft — not released)

This release adds a proof-gated file-upload vulnerability detector for
authorized bug-bounty and penetration-testing scopes.

## Admin and high-sensitive panel inventory

- Classifies administrative logins and management consoles from strong product,
  title/form, or authorization-response evidence collected by the existing
  in-scope HTTP and directory phases.
- Adds a dedicated **Admin & sensitive panels** target tab. Identical response
  fingerprints and common redirect destinations collapse into one row while an
  expandable affected-URL list preserves every host and path.
- Rejects path-only generic pages, documentation mentions, and soft-404 shells,
  preventing a large `/admin` wordlist from turning into dashboard junk.
- Changes the orange target headline to actionable medium-or-higher findings;
  informational/low Nuclei rows, raw backup inventory and operator-triaged false
  positives no longer inflate the vulnerability number.

## XSS context coverage

- Deepens the bounded browser-proof ladder across HTML/SVG events, quoted and
  unquoted attributes, JavaScript strings and template literals, URL sinks,
  comments, raw-text/RCDATA and nested `iframe[srcdoc]` documents.
- Adds mixed-case, separator, autofocus, media-error and SVG animation families
  without reverting to cross-context payload spray.
- Every confirmed XSS still requires a fresh random nonce to execute in Chromium;
  reflection or payload survival alone remains non-actionable.

## Coverage

- Discovers existing multipart upload fields and both structured-object and
  flat base64/data-URI JSON/REST schemas, including sibling filename/MIME
  metadata. Upload routes are no longer dropped merely because they are
  non-reflected or belong to a detected CMS.
- Exercises PHP, JSP/JSPX, classic ASP/ASPX, ColdFusion, SSI and CGI script
  families (including `.phtml`, `.phar`, `.jspx`, `.asp`, `.cer`, `.cfm`,
  `.shtml`, `.cgi`, `.pl`, `.py` and `.rb`), plus case variants,
  double/multiple extensions, encoded-null spellings, semicolon delimiters,
  replacement-filter bypasses, ADS-style names, and trailing-space/dot variants.
- Checks PHP, JSP and ASPX bodies under image MIME types and GIF magic-byte
  polyglots.
- Follows server-disclosed and bounded predictable stored paths, including
  server-side renames.
- Validates stored SVG execution through the existing Chromium verifier.
- Correlates SVG/MVG image-processing SSRF and DOCX/XLSX embedded-XXE through
  Reconner's existing token-attributed OOB lifecycle.
- Confirms ZIP/TAR path traversal only by a second retrieval outside the intended upload
  directory; a marker extracted normally under `/uploads` is an explicit
  negative regression fixture.
- Tests `.htaccess` and `web.config` only by verifying the resulting handler
  effect with a separately uploaded proof file.

## False-positive contract

An HTTP success from the upload endpoint is not evidence. A finding is promoted
only after dangerous retrieval or processing is independently proven. Benign
images served from non-executable storage remain silent, and patched sibling
fixtures are present for every bypass family.

## Nuclei signal quality

- Tightens the bundled Laravel Ignition, phpinfo, WordPress backup and Git HEAD
  matchers so generic documentation/error pages cannot satisfy them.
- Drops behavior-template hits whose only response is 204, redirect, auth
  denial or 404 (open-redirect templates remain correctly exempt).
- Adds strict embedded checks for exposed AWS credentials, Composer auth,
  npm registry credentials and Subversion `wc.db`; each requires format-specific
  proof rather than a filename/status-only match.
- Keeps the built-in/template-operator exclusion list deterministic and
  deduplicated for reproducible scans.
- Runs the embedded pack against local positive and patched fixtures in the
  regression suite; third-party assets are never contacted by these tests.

## Scope and local validation

The detector reuses Reconner's target request identity, host/endpoint scope
gates, insertion-point inventory, candidate lifecycle and structured evidence
store. The complete positive/negative matrix is implemented with local Go
`httptest` servers. Tests do not contact third-party or production assets.

Reproduce the focused suite with:

```bash
go test ./internal/scanner -run TestFileUpload -count=1
go test ./internal/scheduler ./internal/api
```
