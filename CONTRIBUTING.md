# Contributing to AgentGuard

Thanks for considering a contribution. AgentGuard is Apache-2.0 licensed and
welcomes issues, PRs, and discussions from anyone.

---

## Before you start

- Read [ROADMAP.md](ROADMAP.md) to see where the project is heading.
- Read [ARCHITECTURE.md](ARCHITECTURE.md) to understand the layering and
  extension points.
- For non-trivial changes, open an issue or a GitHub Discussion first so we
  can agree on direction before code is written.

---

## What kinds of contributions help most

- **Bug reports with a minimal reproduction** (a failing test is ideal).
- **New filters** behind the `filter.Filter` interface — secret scanners for
  new credential formats, anomaly heuristics, custom verdicts.
- **Policy cookbook entries** — real-world YAML examples for new AI hosts,
  MCP servers, or frameworks.
- **SDK languages** — Node.js/TypeScript, Go, Rust are all wanted.
- **Docs** — especially first-time-user walkthroughs and framework
  integrations.
- **Tests** for existing code paths that don't yet have coverage.

Low-value contributions: typo-only PRs without a user-facing impact,
reformatting existing code, speculative abstraction without a concrete
user.

---

## Development setup

```bash
git clone https://github.com/tkingovr/agent-guard
cd agent-guard

# Build
make build            # -> ./bin/agentguard

# Run unit tests with race detector
make test

# Coverage report
make test-cover       # -> coverage.html

# Lint
make lint             # requires golangci-lint

# Format + vet
make fmt vet
```

Go version: see `go.mod` (currently `go 1.25.5`).

---

## Code style

- `gofmt -s` formatting is enforced.
- `golangci-lint` passes with the repo's `.golangci.yml` (add one if missing).
- Public types/functions have doc comments that describe the *why*, not just
  the *what*. Well-named identifiers carry the *what*.
- Error messages begin lowercase and are wrapped with `fmt.Errorf("thing: %w",
  err)`.
- Avoid panics in library code. Filters that panic must be caught by the
  chain and converted to `deny`.
- No global mutable state outside `cmd/`. Inject dependencies via constructors.

---

## Tests

- Every new filter ships with a unit test in the same package.
- Table-driven tests for policy rule matching.
- Integration tests live under `testdata/` with a mock MCP server
  (`testdata/mock_server`).
- `make test` must pass with `-race` before a PR is ready for review.

---

## Commit messages

- Imperative mood, under 72 chars on the subject line.
- Optional body explains *why*, not *what* (the diff covers *what*).
- Reference issues with `Fixes #123` or `Refs #123`.

Examples:

```
Add Prometheus /metrics endpoint

Exposes verdict counters by rule and tool, approval queue depth,
and filter latency histograms. Uses client_golang, already in go.sum.
```

---

## Pull request checklist

Before requesting review:

- [ ] `make test` passes with `-race`.
- [ ] `make lint` passes.
- [ ] New user-facing behavior is documented in the README or a doc file.
- [ ] `CHANGELOG.md` updated under "Unreleased" (when we have one).
- [ ] For new filters: policy YAML schema updated if needed.
- [ ] For new CLI flags / subcommands: help text is complete and examples in
      the README work.

PRs are reviewed on a best-effort basis by maintainers. Expect back-and-forth
on design for non-trivial changes — it's a security tool, correctness matters.

---

## Security issues

**Do not open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the disclosure policy.

---

## Proposing a roadmap change

See the "How to propose a roadmap change" section at the bottom of
[ROADMAP.md](ROADMAP.md). Significant architectural changes go through an RFC
under `docs/rfcs/NNNN-<slug>.md`.

---

## Licensing of contributions

By submitting a pull request, you agree that your contributions are licensed
under the Apache License, Version 2.0 — the same license as the project. No
CLA is required. The implicit Developer Certificate of Origin applies: you
certify you have the right to submit the code under this license.

---

## Code of Conduct

This project follows the Contributor Covenant v2.1. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (add one before 1.0).

Report conduct issues to the maintainers via the contact listed in
[SECURITY.md](SECURITY.md).
