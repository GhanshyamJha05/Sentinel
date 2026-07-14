# CI integration

## GitHub Actions (reusable action)

```yaml
name: security
on: [push, pull_request]
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: GhanshyamJha05/Sentinel/.github/actions/sentinel@main
        with:
          args: scan all . --format sarif --fail-on high
          output: sentinel.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentinel.sarif
```

## GitHub Actions (go install)

```yaml
- uses: actions/setup-go@v5
  with:
    go-version: '1.22'
- run: go install github.com/GhanshyamJha05/Sentinel@latest
- run: sentinel scan all . --format json --fail-on high
```

## GitHub Actions (Docker)

```yaml
- uses: actions/checkout@v4
- run: |
    docker run --rm -v "$PWD:/src" -w /src \
      ghcr.io/ghanshyamjha05/sentinel:latest \
      scan all . --format json --fail-on high
```

## GitLab CI

```yaml
sentinel:
  image: ghcr.io/ghanshyamjha05/sentinel:latest
  script:
    - sentinel scan all . --format json --fail-on high
  allow_failure: false
```

## Pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/GhanshyamJha05/Sentinel
    rev: v0.1.0
    hooks:
      - id: sentinel
```

Or run locally:

```bash
pre-commit install
```
