# Contributing to Reconner

Thanks for your interest in improving Reconner. Contributions of all kinds are
welcome — bug reports, fixes, new detections, and docs.

## Getting set up

Build and run the whole thing as a normal user — no root required:

```bash
make            # builds the frontend bundle and the `reconner` binary
./reconner       # starts the web application
```

For local development:

- **Backend** (Go ≥ 1.23): `go build ./... && go test ./...`
- **Frontend** (Node ≥ 18): `cd frontend && npm install && npm run dev`

## Guidelines

- Keep changes focused; one logical change per pull request.
- Run `go build ./...`, `go vet ./...` and `go test ./...` before opening a PR.
- For the frontend, make sure `npm run build` (which runs `tsc`) passes.
- Match the style of the surrounding code — naming, comments and structure.
- New Nuclei templates go in `internal/scanner/nucleitemplates/`. Give them a
  strong body matcher (not status-only) so they don't add false-positive noise.

## Reporting bugs

Open an issue with clear reproduction steps, the target type (web/network), and
relevant log output. Please redact any real credentials or private targets.

## Responsible use

Reconner is an offensive-security tool. Only contribute features and tests that
assume **authorized** testing. Do not include payloads or techniques whose only
purpose is untargeted, destructive, or non-consensual activity.
