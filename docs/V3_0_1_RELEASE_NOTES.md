# Reconner v3.0.1

This corrective release finishes the visible v3 product upgrade and makes
upgrades from root-running v2 containers self-healing.

## Product experience

- A new operations-console visual system with a structured shell, command bar,
  stronger hierarchy, clearer page introductions and consistent controls.
- A redesigned command-center dashboard, login experience, metrics, data
  panels, project workspace and first-run empty state.
- A new violet, blue and teal signal palette with quieter semantic surfaces,
  improved contrast, spacing, focus states and responsive behavior.
- Browser autofill can no longer leak the saved username into global target
  search or paint password fields with an unreadable light background.

## Upgrade recovery

- Docker Compose automatically repairs ownership of pre-v3 `/data` volumes and
  drops to uid/gid `10001` before the application starts.
- An undecryptable historical Telegram bot token no longer bricks startup. The
  token alone is reset and disabled while chat permissions remain intact.
- Scan identities, captured requests and evidence remain fail-closed; they are
  never silently discarded when decryption fails.
