# Reconner v3.3.1 authentication-header bypass evidence

This document records bounded, local-only regression evidence. Every endpoint
is an in-process Go `httptest` fixture bound to loopback. No external target was
scanned or actively tested.

## Research basis

The motivating write-up documents a backend that returned protected data when
sent `Authorization: Basic` with no username, password, or encoded credential:
[No Username. No Password. Just a Header](https://medium.com/@0xalr/no-username-no-password-just-a-header-a-3-000-authentication-bypass-9b42432b6c69).

[RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html) defines Basic
credentials as a Base64 encoding of a `user-id:password` pair. A bare scheme is
not a valid Basic credential. [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)
requires a Bearer scheme followed by a non-empty token. [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)
states that invalid or partial credentials should receive a 401 response and
distinguishes that from a 403 response for valid but insufficient credentials.

The existing path/IP techniques remain grounded in the URL override and
front-end/back-end policy discrepancies described by
[PortSwigger's access-control methodology](https://portswigger.net/web-security/access-control)
and [OWASP WSTG authorization testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/05-Authorization/02-Bypassing_Authorization_Schema/).

## Bounded probe matrix

Reconner sends only six fixed, non-secret credential-shape probes:

- bare `Basic` (missing credentials);
- Basic with an invalid token68;
- Basic containing the encoded empty `:` pair;
- bare `Bearer` (missing token);
- Bearer `null`;
- Bearer `undefined`.

These probes test validation semantics; they do not enumerate identities or
guess secrets.

## Proof contract

An initial response must be 401 or 403. Techniques run in one bounded parallel
wave. An apparent 200 triggers a second original request and an exact replay.
The finding is confirmed only when the denied status and body are stable, the
successful body is stable and substantial, and the successful response is not
the same object or another authentication wall.

## Local matrix

Positive fixtures:

- bare Basic against a 401 service;
- bare Basic against a 403 service;
- invalid Basic token68;
- encoded empty Basic user/password;
- missing Bearer token;
- Bearer `null`;
- Bearer `undefined`.

Negative and integration controls:

- a correct server rejects every malformed credential;
- a denial that changes from 401 to 403 during replay is rejected;
- the full scanner selects and persists confirmed findings for both stored 401
  and stored 403 services.

## Reproduction

```bash
go test ./internal/scanner -run '^TestAuthHeaderBypassV331_' -count=3

go test -race ./internal/scanner -run '^TestAuthHeaderBypassV331_' -count=2
```
