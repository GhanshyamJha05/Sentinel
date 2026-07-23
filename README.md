# Sentinel

Unified CLI security scanner for **leaked secrets**, **vulnerable dependencies**, and **common misconfigurations**.

[![CI](https://github.com/GhanshyamJha05/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/GhanshyamJha05/Sentinel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GhanshyamJha05/Sentinel)](https://github.com/GhanshyamJha05/Sentinel/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/GhanshyamJha05/Sentinel)](https://goreportcard.com/report/github.com/GhanshyamJha05/Sentinel)

## Features

- **Secrets** - regex + Shannon entropy detectors (AWS, GCP, Slack, GitHub, Stripe, JWTs, private keys, generic API keys); optional git history via go-git; PR/diff mode with `--git-diff`
- **Dependencies** - parses `go.mod`, `package.json` / lockfiles, `requirements.txt`; queries [OSV.dev](https://osv.dev) with local TTL cache; Go vulns filtered to imports you actually use
- **Misconfigurations** - exposed `.env` files, debug flags, default credentials, weak permissions (Unix), missing security headers, Terraform public exposure / hardcoded secrets
- **CI-ready** - table / JSON / SARIF output, `--fail-on` exit codes, `--git-diff` for PR gates

## Install

```bash
go install github.com/GhanshyamJha05/Sentinel@latest
```

Release packaging is configured with GoReleaser for Homebrew, Docker/GHCR, and binary archives. Those channels should be promoted here after the first release artifacts are published.

Planned release channels:

- Homebrew: `brew install GhanshyamJha05/tap/sentinel`
- Docker: `ghcr.io/ghanshyamjha05/sentinel:latest`
- Binary archives: [GitHub Releases](https://github.com/GhanshyamJha05/Sentinel/releases)

## Quickstart

```bash
sentinel scan all .
sentinel scan secrets ./path
sentinel scan deps ./path
sentinel scan config ./path

# CI gate: fail on Critical/High (default)
sentinel scan all . --format json --fail-on high

# PR mode: only changed files vs main
sentinel scan all . --git-diff origin/main --fail-on high

# Machine-readable / GitHub Code Scanning
sentinel scan all . --format sarif > results.sarif
```

## Example output

```
sentinel security scan
target=/path/to/repo  findings=3  at=2026-07-14T12:00:00Z

CRITICAL  aws-access-key  .env:2  [secret]
  AWS Access Key ID
  snippet: AWS_ACCESS_KEY_ID=AKIA************AMPLE
  fix: Remove the secret, rotate credentials, and add the path to .sentinelignore if this is a false positive.

HIGH  env-file-exposed  .env  [misconfiguration]
  Sensitive file ".env" may contain credentials and should not be committed

MEDIUM  vulnerable-dependency  go.mod  [dependency]
  github.com/gin-gonic/gin@1.6.3 has vulnerability GO-2021-0059
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `sentinel.yaml` | Config file path |
| `--format`, `-f` | `table` | `table`, `json`, or `sarif` |
| `--fail-on` | `high` | Exit 1 if findings are at or above severity (`critical\|high\|medium\|low\|info\|none`) |
| `--no-color` | false | Disable colors |
| `--workers` | NumCPU | Concurrent file workers |
| `--git-history` | false | Also scan git history for secrets |
| `--git-diff` | (off) | Only scan files changed vs a git ref (e.g. `origin/main`); ideal for PRs |
| `-q`, `--quiet` | false | Suppress non-essential output |

Environment variables use the `SENTINEL_` prefix (e.g. `SENTINEL_FORMAT=json`).

## Configuration

Optional `sentinel.yaml`:

```yaml
format: table
fail-on: high
git-history: false
ignore:
  - vendor/
  - "**/*.example"
```

Ignore false positives with `.sentinelignore` (gitignore-style patterns). By default `node_modules`, `vendor`, `.git`, and similar directories are skipped; `.gitignore` is respected for secret scans.

You can also suppress specific dependency advisory IDs with `ignore_vulns:` or entire rule IDs with `ignore_rules:` in `sentinel.yaml`.

## Documentation

- [Detection rules](docs/rules.md)
- [CI integration](docs/ci-integration.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

MIT
