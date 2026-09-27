# API data-exposure workflow

Reconner's `api_data_exposure` module turns separate discovery observations into
one proof-gated workflow:

1. collect request-bound parameter names from JavaScript, forms, OpenAPI and the
   persisted request inventory;
2. correlate the highest-signal names across in-scope API endpoints and sibling
   hosts in the same project;
3. begin with unauthenticated `GET` controls;
4. when an endpoint returns `405`, inspect `Allow` and, only when needed,
   `OPTIONS`; use `POST` only when it is advertised or already observed and the
   route is read-like;
5. reuse an observed JSON or form request shape, with bounded inert values;
6. classify structured response fields without persisting their values;
7. replay the exact request and require the same sensitive-field schema before a
   finding is confirmed.

The workflow never automatically negotiates `PUT`, `PATCH`, `DELETE`, `TRACE`,
or `CONNECT`. Paths containing create/update/delete/payment/upload/account-action
language are excluded from automatic `POST`. Redirects are not followed, each
destination remains target-scoped, and every response body is capped.

## Shipped methodology packs

- **Cross-asset contract correlation:** request-bound JS/OpenAPI names are
  scored once and tried against the highest-signal API routes across approved
  sibling hosts, rather than brute-forcing every word against every URL.
- **405 method recovery:** a failed `GET` becomes an `Allow`/`OPTIONS` decision;
  only an advertised or previously observed read-like `POST` is eligible.
- **415 media-type recovery:** an unsupported JSON request can move to an
  explicitly advertised `Accept-Post` form contract; no blind content-type
  spray is performed.
- **Empty-contract/list exposure:** bounded `{}` or empty-form controls detect
  APIs that return a data collection without requiring an object selector.
- **Projection/expansion checks:** high-signal `fields`, `include`, `expand`,
  search and object-id parameters use type-shaped, non-secret values.
- **Schema stability proof:** the exact unauthenticated request is replayed and
  must produce the same sensitive field-path/class fingerprint with a comparable
  record count.

## Why the workflow exists

Modern API exposure bugs are often missed when scanners treat JavaScript,
parameters, hosts and HTTP methods as unrelated lists. A bundle may describe a
high-value request field while the corresponding route is deployed on a sibling
API host. The route may reject `GET` with `405` but explicitly advertise a
read-oriented `POST` contract. The useful signal is the relationship between
those observations—not any one observation alone.

The design follows these references:

- [PortSwigger API testing](https://portswigger.net/web-security/api-testing)
  recommends mining JavaScript for endpoints, identifying supported methods and
  content types, and warns that method changes can be destructive.
- [OWASP API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
  groups excessive data exposure and object-property authorization under API3.
- [OWASP WSTG: Excessive Data Exposure](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Excessive_Data_Exposure/)
  calls for examining more than one endpoint and comparing the data exposed by
  API responses with what the application actually needs.
- [OWASP WSTG: HTTP Methods](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/06-HTTP_Methods/)
  documents `OPTIONS`/`Allow` discovery and the risk of state-changing verbs.
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
  covers method/content-type validation and sensitive response handling.
- [PortSwigger hidden-input analysis](https://portswigger.net/burp/documentation/desktop/testing-workflow/analyzing/hidden-inputs)
  uses scoped parameter guessing and omitted controls rather than treating every
  response difference as proof.
- [PortSwigger: Listen to the whispers](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)
  emphasizes differential controls and false-positive analysis for site-wide
  hidden inputs.
- [ProjectDiscovery Katana](https://projectdiscovery.io/blog/introducing-katana-the-best-cli-web-crawler)
  demonstrates why JavaScript-aware and rendered crawling are necessary to find
  modern application routes.
- [NIST SP 800-122](https://csrc.nist.gov/pubs/sp/800/122/final) provides the
  context-based basis for identifying and protecting PII.

## Proof and privacy gates

Reconner recognizes key-aware email, phone, postal address, birth date,
government identifier, payment-card, bank-account, health-data, credential
material and authentication-secret classes. It rejects sample domains, masked values, invalid card
numbers, weak one-field contact responses and documentation/sample routes.

Evidence contains only:

- sensitive-data classes;
- normalized JSON field paths;
- record count;
- status and media type;
- a schema fingerprint.

Raw response values are neither copied to the candidate payload nor to finding
evidence. Ordinary contact data requires multiple classes across multiple
records. Government, payment, banking, health or credential material receives a
higher severity, with `critical` reserved for replay-stable multi-record or
multi-field high-impact exposure.

## Local regression matrix

`internal/scanner/api_data_exposure_test.go` provides deterministic local HTTP
fixtures for:

- `405` to advertised JSON `POST` negotiation;
- JS/body parameter correlation;
- credential-free unauthenticated requests;
- replay-stable high-impact PII confirmation;
- raw-value redaction;
- rejection of one-shot/unstable responses;
- rejection of sample/weak contact noise;
- refusal to `POST` to state-changing paths;
- request-bound JavaScript parameter extraction without global object-key noise.

These fixtures are quality and behavior tests against code owned by the project.
They make no requests to external applications.
