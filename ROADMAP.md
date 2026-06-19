# AgentGuard Roadmap

This document describes the MVP (1.0) target and the phased roadmap beyond it.
For a scalable deployment reference, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Status at a glance

AgentGuard already ships a working MCP firewall:

- stdio + Streamable-HTTP MCP proxy
- YAML first-match-wins policy engine
- OPA/Rego engine as an alternative
- JSONL audit log with date rotation and live SSE streaming
- Approval queue with `ask` verdict
- Web dashboard (HTMX + Tailwind)
- Secret scanner (12 patterns + Shannon entropy)
- Sliding-window rate limiting (global + per-tool)
- Python SDK with LangChain + CrewAI integrations
- GitHub Actions CI, goreleaser cross-platform builds

The remaining 1.0 gap is primarily **hardening, distribution, and reach** rather
than new core functionality.

---

## 1.0 — MVP definition

Goal: a tool a security-conscious developer can drop in front of any MCP-capable
AI host and trust in production on a single machine.

### Must-have for 1.0

- [ ] **Dashboard authentication.** Token-based auth (`AGENTGUARD_DASHBOARD_TOKEN`)
      with CSRF protection. A local dashboard that any browser tab can hit is a
      DNS-rebinding hazard for a security product.
- [ ] **Policy hot-reload.** `SIGHUP` or filesystem watch reloads config without
      dropping the proxy connection. Table stakes for iterative policy authoring.
- [ ] **Prometheus `/metrics` endpoint.** Counters for verdicts per rule/tool,
      approval queue depth, denial reasons, filter latency histograms.
      Dependencies already present in `go.sum`.
- [ ] **Node.js / TypeScript SDK.** Most MCP agent tooling lives in JS (Cursor,
      Continue, Zed extensions, AI SDK projects). Python alone under-serves the
      ecosystem.
- [ ] **Docker image.** `ghcr.io/tkingovr/agentguard:latest` multi-arch (amd64,
      arm64). Distroless base. Non-root user.
- [ ] **Homebrew tap + install.sh.** One-line install for macOS/Linux devs.
- [ ] **Docs site.** Installation, first-policy tutorial, policy cookbook,
      integration guides (Claude Desktop, Cursor, Continue, Zed). mdBook, MkDocs,
      or Docusaurus — pick one. Move the policy DSL reference out of the README.
- [ ] **Framework example configs.** `configs/examples/{claude-desktop,cursor,
      continue,zed,codex}.yaml`. Developers copy-paste-and-go.
- [ ] **CHANGELOG.md.** Keep-a-Changelog format. Auto-populated from goreleaser.
- [ ] **CONTRIBUTING.md + SECURITY.md + CODE_OF_CONDUCT.md.** Present but the
      last two still need content.

### Nice-to-have for 1.0 (cut if needed)

- [ ] Tamper-evident audit log (hash-chain per JSONL record)
- [ ] `agentguard doctor` — diagnose common misconfigurations
- [ ] Shell completions (bash, zsh, fish)
- [ ] Policy linter (`agentguard lint`) — detects unreachable rules,
      conflicting matchers, missing default

### Explicitly out of scope for 1.0

- Multi-instance / clustered deployments (see Phase 3)
- Persistent storage beyond JSONL (see Phase 3)
- Cryptographic agent identity (see Phase 2)
- Hosted SaaS (intentionally: AgentGuard stays open source end-to-end)

---

## Phase 1 — Observability & Reach (1.1 – 1.3)

Goal: make AgentGuard production-friendly for teams and easy to integrate.

- **OpenTelemetry traces.** Every filter chain produces a trace with filter
  spans; denials carry the matched rule as an attribute. OTel deps already
  present.
- **Notification sinks.** Slack, Discord, PagerDuty, generic webhooks on
  `deny`/`ask`/high-entropy-secret events. Pluggable `Sink` interface.
- **Go SDK.** First-class Go module for programmatic embedding (`agentguard.Check`,
  `agentguard.Chain`).
- **SSE → WebSocket upgrade path.** Dashboard handles dropped connections more
  gracefully over flaky networks.
- **RBAC on the dashboard.** Viewer / approver / admin roles, backed by static
  tokens for now (OIDC in Phase 3).
- **Audit log sinks.** Ship audit records to S3, CloudWatch, Loki, Splunk, or a
  generic syslog target in addition to JSONL.
- **Replay mode.** `agentguard replay <audit.jsonl>` re-runs recorded traffic
  against a new policy — lets users safely test policy changes.
- **Policy linter & test framework.** `.agentguard-test.yaml` files describe
  expected verdicts for sample inputs; `agentguard test` runs them in CI.

---

## Phase 2 — Identity & Provenance (1.4 – 1.6)

Goal: make every agent action cryptographically attributable.

- **Agent identity.** Each agent gets a signed identity (Ed25519 keypair).
  Policies can match on `agent.id`, `agent.team`, `agent.trust_level`.
- **Capability tokens.** Short-lived, scoped, revocable tokens that authorize
  an agent to perform a specific action class. Think macaroons / biscuit-auth.
- **Signed audit log.** Each record is hash-chained to the previous and
  periodically notarized (Rekor transparency log or local Merkle root). Gives
  the audit stream the tamper-evidence regulators and insurers will demand.
- **Human-in-the-loop receipts.** When a human approves an `ask`, the approval
  is signed with the approver's key and bound to the request hash. Provable
  later: "a real human approved this wire transfer at this time."
- **Tool provenance.** When an MCP tool is registered, AgentGuard records its
  source (npm package + version, binary hash, remote URL) so policies can
  match on `tool.source` and users can audit their agent's supply chain.
- **Memory-write inspection.** Filter outbound writes to agent long-term
  memory stores (inspired by the memory-poisoning threat class) — AgentGuard
  can veto suspicious memory updates before they persist.

---

## Phase 3 — Fleet & Federation (2.0)

Goal: single-node tool becomes deployable infrastructure for orgs and
communities.

- **Control plane / data plane split.** Policy server ships signed policy
  bundles to many AgentGuard workers. Workers remain fully functional offline
  with a cached bundle.
- **Pluggable storage.** Audit store behind a `Store` interface:
  PostgreSQL, ClickHouse, S3/MinIO, SQLite (default local).
- **SPIFFE / SPIRE integration.** Workload identity for multi-cluster
  AgentGuard deployments; reuses existing org PKI.
- **OIDC for the dashboard.** Delegate auth to Okta, Keycloak, Auth0, GitHub.
- **Multi-tenant isolation.** One AgentGuard cluster serves many teams with
  tenant-scoped policies, audit logs, and approval queues.
- **Kubernetes-native deployment.** Helm chart + operator. Sidecar pattern for
  in-cluster agent workloads; standalone service for remote MCP traffic.
- **Federation.** Cross-org agent trust: mutual attestation, revocation lists,
  shared deny-feeds. Inspired by CT logs and SPIRE federation.

---

## Phase 4 — Intelligence (2.x+)

Goal: AgentGuard learns. Entirely community-owned data where feasible.

- **Behavioral anomaly detection.** On-device ML flags outliers in an agent's
  tool-call distribution, argument entropy, timing, and chain depth.
- **Prompt-injection classifier.** Optional inbound filter inspects tool
  arguments for known jailbreak / injection patterns. Ships with an
  open-weights base model.
- **Community threat feed.** Opt-in, signed feed of known-bad patterns,
  malicious npm packages shipping as MCP servers, compromised tool versions.
  Federated, not centralized.
- **Policy co-pilot.** LLM-assisted policy authoring: propose policy diffs
  from recent audit traffic; human reviews and merges.

---

## Non-goals

- **Hosted SaaS offering.** AgentGuard stays open source and self-hostable.
  Commercial offerings (if any) live in downstream projects, never in this
  repo's roadmap.
- **MCP server implementation.** AgentGuard proxies servers; it does not
  become one. Tool execution stays with the real server.
- **Full-blown SIEM.** AgentGuard emits to SIEMs, it is not one.
- **Model-layer interception.** AgentGuard operates at the MCP boundary (tool
  calls). Intercepting the raw model prompt is a different architectural layer
  and belongs in another project.

---

## How to propose a roadmap change

Open a discussion in GitHub Discussions under the `roadmap` category, or a
draft PR that edits this file. Significant changes go through an RFC in
`/docs/rfcs/NNNN-<slug>.md`.
