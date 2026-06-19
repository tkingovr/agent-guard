# AgentGuard Architecture

This document describes the current architecture and the scale-up path from a
laptop install to a fleet deployment. Companion to [ROADMAP.md](ROADMAP.md).

---

## Design principles

1. **Default deny.** Policy evaluates to `deny` when no rule matches. Explicit
   allows are the only way through.
2. **Fail closed.** Any filter error, parse error, or policy engine panic
   returns `deny`, never `allow`. A broken AgentGuard is a locked AgentGuard.
3. **Transparent.** Every decision is logged with the matched rule and reason.
   Users never have to guess why something was blocked.
4. **Local by default.** Single-binary, single-machine deployment with no
   network dependencies is always supported. Fleet features are additive.
5. **Pluggable at the seams.** Policy engines, audit sinks, approval backends,
   and notification channels are all interfaces. New integrations are small
   PRs, not core refactors.
6. **Protocol-faithful.** AgentGuard never silently rewrites MCP payloads. It
   forwards, denies, or pauses — nothing in between.

---

## Current architecture (single-node)

```
┌─────────────────────────┐
│  AI Host                │
│  (Claude Desktop,       │
│   Cursor, Zed, Continue)│
└───────────┬─────────────┘
            │ spawns / connects
            ▼
┌─────────────────────────┐       ┌──────────────────┐
│  AgentGuard             │◄─────►│  Web Dashboard   │
│  ┌───────────────────┐  │  API  │  (HTMX + SSE)    │
│  │ Filter Chain      │  │       └──────────────────┘
│  │ 1. Parse          │  │
│  │ 2. Secret scan    │  │       ┌──────────────────┐
│  │ 3. Rate limit     │  │──────►│  Audit Store     │
│  │ 4. Policy (YAML   │  │       │  JSONL + index   │
│  │    or OPA/Rego)   │  │       └──────────────────┘
│  │ 5. Approval queue │  │
│  │ 6. Audit          │  │       ┌──────────────────┐
│  └───────────────────┘  │──────►│  Metrics         │
└───────────┬─────────────┘       │  (Prom, planned) │
            │ forwards allowed    └──────────────────┘
            ▼
┌─────────────────────────┐
│  Real MCP Server        │
│  (fs, postgres, shell…) │
└─────────────────────────┘
```

### Components

| Component | Package | Responsibility |
|---|---|---|
| CLI | `cmd/agentguard/cli` | Subcommands: `proxy`, `httpproxy`, `serve`, `dashboard`, `check`, `version` |
| stdio proxy | `internal/proxy/stdio` | MITM between host stdin/stdout and subprocess |
| HTTP proxy | `internal/proxy/http` | Reverse proxy for MCP Streamable HTTP transport |
| JSON-RPC codec | `internal/jsonrpc` | Parse + build MCP messages |
| Filter chain | `internal/filter` | Ordered pipeline; any filter can set the verdict |
| Policy engines | `internal/policy` | YAML first-match-wins + OPA/Rego |
| Approval queue | `internal/approval` | Pauses `ask` verdicts until approver decides |
| Audit store | `internal/audit` | JSONL writer, date rotation, SSE fan-out |
| Dashboard | `internal/dashboard` | HTTP server, templates, SDK API |
| Config | `internal/config` | YAML policy loader + defaults |
| API types | `api/` | Public surface: verdicts, audit records, JSON-RPC |

### Data flow — single message

1. AI host writes a JSON-RPC line to AgentGuard's stdin (or POSTs via HTTP).
2. `ParseFilter` extracts `method`, `tool`, `arguments` from the raw bytes.
3. `SecretScannerFilter` inspects arguments for credential patterns + high
   Shannon entropy tokens.
4. `RateLimitFilter` increments sliding-window counters (global + per-tool).
5. `PolicyFilter` evaluates YAML or OPA rules against `EvalInput`, produces
   `Verdict { allow | deny | ask | log }`.
6. `AuditFilter` appends a record to the JSONL log and fans out to SSE
   subscribers.
7. The proxy loop acts on the verdict:
   - `allow` / `log` → forward to real server, stream response back
   - `deny` → synthesize JSON-RPC error, return to host, never forward
   - `ask` → publish to approval queue, block until approver decides or
     `approval_timeout` elapses, then allow or deny accordingly

### Concurrency model

- Proxy runs two goroutines per connection: inbound and outbound pipes.
- Filter chain is synchronous per message — no shared mutable state inside
  filters beyond the explicit `FilterContext`.
- Approval queue blocks the inbound goroutine; the outbound goroutine remains
  free so the subprocess can still emit notifications while a request is
  pending.
- Dashboard HTTP server runs in its own goroutine, reads from audit store and
  approval queue via `context.Context`-scoped subscriptions.
- Audit writer uses a single goroutine behind a buffered channel to serialize
  JSONL appends without per-message mutex contention.

---

## Extension points

The codebase is already interface-driven at the right places. Each of these is
a stable boundary for community contributions and future pluggable backends.

### `filter.Filter`

```go
type Filter interface {
    Name() string
    Process(ctx context.Context, fc *FilterContext) error
}
```

Any filter can inspect `FilterContext`, set a verdict, attach metadata, or
short-circuit the chain. All built-in checks (parse, secret, rate-limit,
policy, audit) are just filters.

### `policy.Engine`

YAML and OPA engines implement a common `Evaluate(EvalInput) EvalResult`
contract. Future engines (WASM-based, CEL, regex-only for edge devices) plug
in here.

### `audit.Store`

JSONL store today. Phase 3 adds PostgreSQL, ClickHouse, S3, Loki, syslog
implementations behind the same interface.

### `approval.Backend` (planned)

Current approval queue is in-memory. A `Backend` interface will let the queue
persist to disk (restart survival), share across instances (Redis), or route
approvals out-of-band (Slack buttons, PagerDuty, mobile push).

### `sink.Notifier` (planned)

Verdict events emit to a bus of notifiers: Slack, PagerDuty, webhook, syslog.
Sinks are filtered by verdict type, rule name, or tool.

---

## Scale-up tiers

AgentGuard is designed so a user can climb the tier ladder without rewriting
policies or replacing the binary.

### Tier 1 — Single user, single machine (today)

- One AgentGuard binary per AI host.
- Config, audit log, and dashboard are all local to `~/.agentguard/`.
- No network dependencies. Works offline.

**Target user:** individual developer, security-conscious AI power user.

### Tier 2 — Team (Phase 1 & early Phase 3)

- Each developer still runs AgentGuard locally.
- Central policy repository (git). `agentguard` pulls the latest signed bundle
  on start and on `SIGHUP`.
- Audit logs ship to a shared sink (Loki, S3, SIEM).
- Notifications (Slack, PagerDuty) fire on team-relevant events.
- Dashboard tokens issued per-dev.

**Target user:** small engineering team standardizing agent guardrails.

### Tier 3 — Org / fleet (Phase 3)

- **Control plane:** `agentguard-control` service owns policy bundles, signs
  them, serves them over HTTPS with mTLS or OIDC auth. Stores audit metadata
  in PostgreSQL/ClickHouse.
- **Data plane:** many `agentguard` workers run as sidecars, system services,
  or standalone processes. Each caches the last known bundle and keeps
  operating if the control plane is unreachable.
- **Storage:** pluggable. Audit bulk data in S3/object storage; hot metadata
  in PostgreSQL; metrics in Prometheus.
- **Identity:** SPIFFE/SPIRE issues workload certs; OIDC gates the dashboard.
- **Deployment:** Helm chart, operator, Terraform modules.

**Target user:** platform / security team rolling out MCP tooling across a
company.

### Tier 4 — Federation (Phase 3+ / Phase 4)

- Cross-org agent identity federation (SPIFFE federation, verifiable
  credentials).
- Signed threat feeds subscribed to by opt-in deployments, similar to
  CT logs or Bloom-filter-based blocklists.
- Community-owned transparency log for high-severity deny events (optional
  publication, privacy-preserving).

**Target user:** communities of orgs sharing threat signal (e.g., FS-ISAC
equivalent for AI agents).

---

## Security considerations

- **Dashboard exposure.** Today the dashboard listens on `127.0.0.1` without
  auth. Before 1.0, the dashboard requires a token (see ROADMAP). CSRF tokens
  on all state-changing endpoints.
- **Host isolation.** AgentGuard runs with the privileges of the calling AI
  host. It does not grant capabilities; it only restricts them. Never run
  the AI host as root to compensate for AgentGuard.
- **Policy tampering.** Local policy files are trusted as much as the host
  filesystem. Fleet deployments verify signed bundles (Phase 3).
- **Audit integrity.** JSONL is append-only but not tamper-evident. Signed
  hash-chain lands in Phase 2.
- **Secret scanner false positives.** Entropy-based matches can flag legitimate
  long random strings. Users can narrow the scanner with per-rule exemptions.
- **Side channels.** AgentGuard does not defend against timing or resource
  side-channels between host and tool. Out of scope.
- **Denial of service.** Rate limits apply per-tool and globally; filter
  latency is bounded. A malicious MCP server can still flood outbound
  responses; audit store is the backstop.

---

## Testing strategy

- Unit tests live next to each package (`*_test.go`).
- `testdata/` holds JSON-RPC fixtures, mock MCP server, sample policies.
- Integration tests spin up the proxy with a mock server subprocess and
  validate end-to-end verdicts.
- Phase 1 adds a policy test framework (`agentguard test`) usable in
  downstream repos to gate policy changes in CI.

---

## Versioning

AgentGuard follows SemVer from 1.0 onwards.

- **Major:** breaking changes to policy YAML schema, CLI flags, or API types
  in `api/`.
- **Minor:** new filters, verdicts, SDK languages, storage backends.
- **Patch:** bug fixes, security fixes, dependency bumps.

The policy YAML schema carries its own `version:` field for forward-compat.
