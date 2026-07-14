# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--git-diff <ref>` to scan only files changed vs a git ref (PR-friendly)
- Go dependency findings filtered by actually imported packages (`go list -deps`)
- Terraform IaC checks: public SG/S3 exposure and hardcoded secrets

## [0.1.0] - 2026-07-14

### Added

- Initial release of `sentinel` CLI
- Secrets scanner with regex + Shannon entropy and optional git history
- Dependency scanner via OSV.dev (go.mod, package.json, requirements.txt)
- Misconfiguration checks (env files, debug flags, default creds, permissions, headers)
- Unified `scan all` with table / JSON / SARIF output and `--fail-on` exit codes
- Docker image, GoReleaser config, GitHub Action, and pre-commit hook

[Unreleased]: https://github.com/GhanshyamJha05/Sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GhanshyamJha05/Sentinel/releases/tag/v0.1.0
