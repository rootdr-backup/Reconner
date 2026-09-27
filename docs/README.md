# Reconner documentation

This directory is organized by the job an operator or contributor is trying to
complete. Start with the short guides; use evidence and planning documents when
you need detector-level detail.

## Start here

| Document | Use it for |
|---|---|
| [Project overview](../README.md) | Product overview, quick start, verification model, and current capabilities |
| [Operator guide](OPERATOR_GUIDE.md) | Installation, upgrades, backups, sizing, recovery, and troubleshooting |
| [Scanning guide](SCANNING_GUIDE.md) | Scope types, web/network plans, phase controls, corpora, evidence, and exports |
| [Docker reference](../README.Docker.md) | Image composition, Compose layout, persistence, and runtime capabilities |
| [Capability matrix](V3_CAPABILITY_MATRIX.md) | Module prerequisites, positive-proof contracts, and support boundaries |
| [API data-exposure workflow](API_DATA_EXPOSURE_WORKFLOW.md) | Research basis, request-safety gates, method negotiation, and local regression corpus |

## Quality and verification evidence

| Document | Focus |
|---|---|
| [Quality evidence review](QUALITY_EVIDENCE_REVIEW.md) | Cross-module detector quality and reproducible local evidence |
| [v3.4 XSS state coverage](V3_4_XSS_STATE_COVERAGE_EVIDENCE.md) | Browser-state and XSS context coverage |
| [v3.2 XSS quality evidence](V3_2_XSS_QUALITY_EVIDENCE.md) | Context matrix, negatives, and performance evidence |
| [v3.3 web behavior evidence](V3_3_WEB_BEHAVIOR_QUALITY_EVIDENCE.md) | 401/403, host header, CRLF, prototype pollution, and cache behavior fixtures |
| [v3.3.1 auth-header evidence](V3_3_1_AUTH_HEADER_BYPASS_EVIDENCE.md) | Stable-control authentication-header confusion checks |
| [v3 release audit](V3_RELEASE_AUDIT.md) | Release-gate evidence and disclosed constraints |
| [v3 hardening status](V3_HARDENING_STATUS.md) | Hardening work and remaining operational gates |

All detector regression fixtures are local and deterministic. Passing a named
fixture matrix is not presented as a universal detection percentage for every
application, framework, network, or policy.

## Architecture and engineering plans

| Document | Focus |
|---|---|
| [v3 stability and release plan](V3_STABILITY_RELEASE_PLAN.md) | Correctness, packaging, soak, upgrade, and release gates |
| [Vulnerability engine roadmap](VULNERABILITY_ENGINE_ROADMAP.md) | Detector architecture and staged improvements |
| [2026 Q3 research backlog](RESEARCH_BACKLOG_2026Q3.md) | Source-grounded coverage backlog and priorities |
| [Parameter discovery review](PARAMETER_DISCOVERY_REVIEW.md) | Parameter inventory and request reconstruction gaps |
| [Hybrid guided crawl plan](HYBRID_GUIDED_CRAWL_PLAN.md) | Rendered-state discovery and bounded interaction design |

Planning documents describe intent and may include work that is not yet part of
the shipped runtime. The capability matrix and current release notes are the
authoritative user-facing description of shipped behavior.

## Release notes

- [v3.4.0](V3_4_0_RELEASE_NOTES.md)
- [v3.3.1](V3_3_1_RELEASE_NOTES.md)
- [v3.3.0](V3_3_0_RELEASE_NOTES.md)
- [v3.2.0](V3_2_0_RELEASE_NOTES.md)
- [v3.1.0](V3_1_0_RELEASE_NOTES.md)
- [v3.0.3](V3_0_3_RELEASE_NOTES.md)
- [v3.0.2](V3_0_2_RELEASE_NOTES.md)
- [v3.0.1](V3_0_1_RELEASE_NOTES.md)

GitHub Releases remain the canonical source for tags, release assets, and
publication status.

## Contributing and support

- [Contribution guide](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [MIT license](../LICENSE)
- [Issue tracker](https://github.com/rootdr-backup/Reconner/issues)

Report product bugs, false positives, missed local fixtures, and documentation
problems through the issue tracker with sanitized logs and a minimal
reproduction. Report vulnerabilities in Reconner itself through the private
process in the security policy.
