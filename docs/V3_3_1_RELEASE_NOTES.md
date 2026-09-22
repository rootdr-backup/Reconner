# Reconner v3.3.1

This patch release extends the existing access-control bypass module from 403
surfaces to both 401 and 403 responses and adds deterministic detection for
credential-presence confusion.

## Detection changes

- Discovers protected services returning either `401 Unauthorized` or `403
  Forbidden`.
- Adds the reported bare `Authorization: Basic` technique, where a backend
  incorrectly treats the presence of an authentication scheme as a valid
  identity.
- Covers bounded related parser/validation gaps: invalid Basic token68, an
  encoded empty Basic user/password pair, a missing Bearer token, and the common
  `null`/`undefined` Bearer placeholders.
- Does not guess or brute-force usernames, passwords, API keys, or tokens.

## False-positive controls

A response is promoted only when:

1. the original request produces the same 401 or 403 status and materially
   equivalent denial body twice;
2. the exact malformed credential produces a 200 response twice;
3. both successful bodies are materially equivalent;
4. the successful body differs from the denial response, is substantial, and
   does not resemble a login/authentication wall.

Authorization-header findings are stored as high severity with PoC confidence.
Path normalization results retain their lower candidate confidence.

## Local validation

All fixtures are in-process Go `httptest` servers on loopback. No third-party
host was probed. The matrix includes seven positive 401/403 credential cases,
a server that correctly rejects every malformed credential, an unstable denial
status control, and an end-to-end persistence test proving that both 401 and 403
services are selected.

Detailed methodology, sources and reproduction commands are in
[v3.3.1 authentication-header bypass evidence](V3_3_1_AUTH_HEADER_BYPASS_EVIDENCE.md).
