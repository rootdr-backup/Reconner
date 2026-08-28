# Security Policy

## Reporting a vulnerability

If you find a security issue **in Reconner itself** (not in a target you're
scanning), please report it privately rather than opening a public issue.

- Telegram: [@rootdr_research](https://t.me/rootdr_research)

Include a description, affected version/commit, and reproduction steps. Please
give a reasonable window to fix the issue before any public disclosure.

## Scope

Reconner is a self-hosted tool. It exposes an authenticated web dashboard —
**do not** expose it directly to the public internet without putting it behind
your own authentication/VPN and TLS. Change the default password immediately
(the app forces this on first login).

## Responsible use

Reconner performs active scanning and exploitation checks. Only use it against
systems you own or are explicitly authorized to test. Misuse is your
responsibility, not the author's.
