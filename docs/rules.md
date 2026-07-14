# Detection rules

How to suppress false positives: add a gitignore-style pattern to `.sentinelignore` in the project root, or set `ignore:` in `sentinel.yaml`.

## Secrets

| Rule ID | Severity | What it detects |
|---------|----------|-----------------|
| `aws-access-key` | CRITICAL | AWS Access Key IDs (`AKIA…`) |
| `aws-secret-key` | CRITICAL | AWS secret access key assignments (with entropy gate) |
| `gcp-api-key` | HIGH | Google Cloud API keys (`AIza…`) |
| `slack-token` | HIGH | Slack bot/user tokens (`xox…`) |
| `github-token` | CRITICAL | GitHub PATs (`ghp_`, `gho_`, etc.) |
| `stripe-key` | CRITICAL | Stripe secret/restricted keys |
| `private-key` | CRITICAL | PEM private key headers |
| `jwt` | MEDIUM | JWT-shaped bearer tokens |
| `generic-api-key` | MEDIUM | `api_key=` / `access_token=` assignments with high entropy |
| `high-entropy-string` | LOW | Password/secret/token assignments with very high entropy |

Secrets are always **redacted** in output (prefix/suffix only). Use `--git-history` to also walk commits via go-git.

## Dependencies

| Rule ID | Severity | What it detects |
|---------|----------|-----------------|
| `vulnerable-dependency` | varies (from OSV) | Known CVEs / advisories for packages in `go.mod`, `package.json` (+ lockfiles), `requirements.txt` |

Lookups use the free [OSV.dev](https://osv.dev) batch API with a local file cache under `~/.cache/sentinel/osv` (24h TTL) and retry/backoff on rate limits.

## Misconfigurations

| Rule ID | Severity | What it detects |
|---------|----------|-----------------|
| `env-file-exposed` | HIGH | `.env`, `.pem`, `.key`, credential-named files present in the tree |
| `debug-enabled` | MEDIUM | `DEBUG=true`, `APP_DEBUG`, `"debug": true`, `NODE_ENV=development`, etc. |
| `default-credentials` | HIGH | Default passwords in Dockerfiles / compose / configs (`admin`, `password`, `root`, …) |
| `weak-permissions` | HIGH | World-readable/writable sensitive files (Unix only) |
| `missing-security-headers` | LOW | nginx/Apache-style configs missing HSTS, CSP, XFO, XCTO |
