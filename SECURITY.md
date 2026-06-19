# Security Policy

AgentGuard is a security tool. We take vulnerability reports seriously and aim
to respond quickly.

---

## Supported versions

Until the 1.0 release, only the latest tagged release on `main` is supported.
After 1.0, the current minor release and the previous minor release will
receive security patches.

| Version | Supported |
|---------|-----------|
| main / latest | Yes |
| pre-1.0 tags | No |

---

## Reporting a vulnerability

**Please do not report security issues via public GitHub issues,
discussions, or pull requests.**

Use one of the following private channels:

1. **Preferred:** GitHub's private vulnerability reporting — open the
   repository's **Security** tab and click *Report a vulnerability*.
2. **Alternative:** email the maintainers directly (see the maintainers list
   in the repo once established).

Include, as best you can:

- A description of the issue and its impact.
- A minimal reproduction (policy file, command, sample input).
- The version or commit hash you tested against.
- Any mitigations you've identified.

---

## What to expect

- **Acknowledgement:** within 72 hours.
- **Initial assessment:** within 7 days (severity, affected versions, fix
  plan).
- **Fix target:**
  - Critical (remote code execution, policy bypass): 7 days.
  - High (auth bypass, sensitive data leak): 30 days.
  - Medium / Low: next scheduled release.
- **Coordinated disclosure:** we will work with you on a disclosure timeline.
  Default embargo is 90 days from the initial report or until a fix ships,
  whichever is sooner. We are happy to credit reporters in the release notes
  and advisory.

A CVE will be requested for any issue with a CVSS score of 4.0 or higher.

---

## Scope

In scope:

- The `agentguard` binary and all packages under `internal/`, `api/`, `cmd/`.
- Official SDKs under `sdk/`.
- Default policy configurations shipped in `configs/`.
- The web dashboard and its HTTP API.

Out of scope:

- Third-party MCP servers proxied through AgentGuard — report those upstream.
- AI hosts (Claude Desktop, Cursor, Zed, Continue, etc.) — report those
  upstream.
- Denial of service by a malicious MCP server flooding outbound responses
  (AgentGuard emits to the audit log; downstream rate-limiting is the user's
  responsibility).
- Policies authored by users that permit dangerous actions — AgentGuard
  enforces policy, it does not write it.

---

## Threat model

AgentGuard assumes:

- The AI host is **untrusted** relative to the user's system boundary. The
  host may be manipulated into issuing malicious tool calls via prompt
  injection or compromised plugins.
- The MCP server is **semi-trusted**. It may be buggy or over-permissive, but
  not actively malicious under normal operation. Supply-chain compromise of an
  MCP server is a concern and is mitigated by tool provenance (Phase 2).
- The user running AgentGuard is **trusted**. AgentGuard runs with the user's
  privileges.
- The policy file is **trusted** and loaded from a path the user controls. In
  fleet deployments (Tier 3), signed policy bundles replace this assumption.
- The dashboard is **local-only by default**. Exposing it on non-loopback
  addresses without authentication is a user configuration error.

AgentGuard defends against:

- Tool-call exfiltration (SSH keys, env vars, home directory traversal).
- Secret leakage in tool arguments.
- Runaway tool-call rates.
- Unreviewed high-impact actions (writes, shell commands, API calls).

AgentGuard does **not** defend against:

- A user who writes a policy that explicitly allows a dangerous action.
- Compromise of the host OS itself.
- Model-layer attacks that occur before the MCP boundary (prompt injection
  inside the agent's reasoning loop that does not result in a tool call — at
  that point, there's nothing for AgentGuard to inspect).
- Side channels (timing, resource usage) between agent and tool.

---

## Disclosure history

Disclosed vulnerabilities will be listed here with CVE, affected versions,
and a summary once AgentGuard has shipped 1.0 and had its first advisory.
