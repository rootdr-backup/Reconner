# Fork workflow

This repository is a personal fork. Keep `main` as the trunk and merge upstream
releases into it. Do not rebase `main` after it is pushed.

## Remotes

| Name | URL | Role |
| --- | --- | --- |
| `origin` | `https://github.com/ItsNilDev/Reconner` | Your fork |
| `upstream` | `https://github.com/rootdr-backup/Reconner.git` | Source project |

Check them with:

```bash
git remote -v
```

## Branches

- `main` — your trunk. Upstream releases plus local patches.
- `backup/void-fixes-before-squash` — pre-compaction history. Keep it local.
- `feat/<name>` — short-lived work branches, cut from `main`.

## Update from upstream

```bash
git switch main
git fetch upstream --tags
git merge upstream/main
```

Resolve conflicts, then verify:

```bash
gofmt -l internal/
go build ./...
go test ./internal/scanner/ ./internal/scheduler/ ./internal/api/ ./internal/database/ -count=1
cd frontend && npm test && npm run build && cd ..
```

Commit the merge if Git did not create it automatically, then push:

```bash
git push origin main
```

### Resolving a conflict

```bash
git status
git diff --name-only --diff-filter=U
# edit each conflicted file
git add <file>
git commit
```

Keep the local `docker-compose.yml` changes out of the commit. It is usually
modified on purpose for the local deployment.

## Local feature work

```bash
git switch -c feat/my-change main
# edit, test, commit
git switch main
git merge --no-ff feat/my-change
git push origin main
```

Use `--no-ff` so the feature stays visible in history.

## Deploy after a code change

The image contains local patches, so rebuild it. Do not use `docker compose pull`
alone.

```bash
docker compose stop reconner
mkdir -p backups
docker compose cp reconner:/data "./backups/reconner-data-$(date +%Y%m%d-%H%M%S)"
docker compose up -d --build reconner
curl -fsS http://localhost:8080/api/health
```

## Rules

1. Do not use GitHub's "Sync fork" button on `main`. It tries to fast-forward
   the fork to upstream and does not fit a trunk with local commits.
2. Do not rebase `main` after it is pushed.
3. Rebase only feature branches that are not shared.
4. Use `--force-with-lease` only after a deliberate history rewrite. Never
   plain `--force`.
5. Merge upstream into `main`; do not reset `main` to upstream.

## Recovery

Inspect the old pre-compaction history:

```bash
git log --oneline backup/void-fixes-before-squash
git diff backup/void-fixes-before-squash main
```

Do not run `git reset --hard` while `docker-compose.yml` is modified. Stash it
first:

```bash
git stash push docker-compose.yml
git reset --hard <commit>
git stash pop
```
