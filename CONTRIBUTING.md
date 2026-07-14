# Contributing

Thanks for improving sentinel.

## Development setup

```bash
git clone https://github.com/GhanshyamJha05/Sentinel.git
cd sentinel
make deps
make test
make build
./bin/sentinel --help
```

## Adding a secret detection rule

1. Open `internal/secrets/rules.go` and append a `Rule` to `DefaultRules()`.
2. Prefer a capturing group for the secret itself so redaction works.
3. Set `EntropyMin` when the pattern is broad (reduces false positives).
4. Add a table-driven case in `internal/secrets/rules_test.go`.
5. Document the rule in `docs/rules.md`.

## Adding a misconfiguration check

1. Create a type implementing `misconfig.Check` (`ID`, `Description`, `Run`).
2. Register it in `DefaultChecks()` in `internal/misconfig/checks.go`.
3. Add fixtures under `testdata/misconfig/` and assert in `checks_test.go`.
4. Document in `docs/rules.md`.

## Code style

- Keep packages focused under `internal/`.
- Prefer table-driven tests.
- Never print full secrets — always redact.
- Run `make lint` and `make test` before opening a PR.

## Release

Tags like `v0.1.0` trigger GoReleaser via GitHub Actions.
