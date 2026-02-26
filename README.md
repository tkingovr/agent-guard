# AgentGuard

**Open-source firewall and audit layer for AI agents.**

AgentGuard intercepts MCP (Model Context Protocol) tool calls, evaluates them against configurable policies, and provides real-time audit logging with a web dashboard. It acts as a MITM proxy between AI hosts (Claude Desktop, Cursor, etc.) and MCP servers.

## Features

- **MCP stdio proxy** — sits between AI host and MCP server, inspecting every JSON-RPC message
- **MCP HTTP proxy** — reverse proxy for Streamable HTTP transport
- **YAML policy engine** — first-match-wins rules with method/tool/argument matching and regex support
- **Default-deny security** — blocks everything not explicitly allowed
- **Web dashboard** — real-time audit log, approval queue, policy viewer (HTMX + Tailwind)
- **Audit logging** — JSONL append-only logs with date-based rotation and live SSE streaming
- **Approval queue** — `ask` verdict pauses execution for human approval via dashboard
- **CLI dry-run** — test policies without running the proxy
- **4 verdicts** — `allow`, `deny`, `ask`, `log`
- **SDK API** — `/api/v1/check` endpoint for programmatic policy evaluation
- **OPA/Rego engine** — embedded Open Policy Agent for complex policy logic
- **Secret scanner** — 12 regex patterns + Shannon entropy analysis to block leaked credentials
- **Rate limiting** — sliding window per-tool and global rate limits

## Quick Start

```bash
# Build
make build

# Test a policy rule (dry-run)
./bin/agentguard check -c configs/default.yaml --method tools/call --tool read_file --args '{"path":"/tmp/test"}'

# Run the stdio proxy
./bin/agentguard proxy -c configs/default.yaml -- npx @modelcontextprotocol/server-filesystem ~/projects

# Run proxy + web dashboard together
./bin/agentguard serve -c configs/default.yaml -- npx @modelcontextprotocol/server-filesystem ~/projects
# Then open http://127.0.0.1:8080

# Run HTTP proxy for Streamable HTTP transport
./bin/agentguard httpproxy -c configs/default.yaml --target http://localhost:4000/mcp --listen :3000

# Dashboard only (view existing audit logs)
./bin/agentguard dashboard -c configs/default.yaml
```

## Policy Example

```yaml
version: 1
settings:
  default_action: deny

rules:
  # Deny rules first (first-match-wins)
  - name: block-ssh-keys
    match:
      method: "tools/call"
      arguments:
        _any_value:
          regex: "(\\.ssh/|id_rsa|id_ed25519)"
    action: deny
    message: "SSH key access blocked"

  - name: block-dangerous-commands
    match:
      method: "tools/call"
      arguments:
        _any_value:
          regex: "(rm\\s+-rf\\s+/|curl.*\\|.*bash)"
    action: deny
    message: "Dangerous command pattern blocked"

  # Allow rules after deny rules
  - name: allow-initialize
    match:
      method: "initialize"
    action: allow

  - name: allow-read-file
    match:
      method: "tools/call"
      tool: "read_file"
    action: allow

  - name: ask-write-file
    match:
      method: "tools/call"
      tool: "write_file"
    action: ask
    message: "File write requires approval"
```

Rules are evaluated top-to-bottom, first match wins (like iptables). Put deny rules before allow rules for proper security.

## Architecture

```
AI Host (Claude Desktop, Cursor, etc.)
    |
    | spawns AgentGuard as "MCP server"
    v
AgentGuard Proxy (stdin/stdout or HTTP)
    |
    | Filter Chain:
    | 1. ParseFilter — extract method, tool, arguments
    | 2. PolicyFilter — evaluate YAML rules -> verdict
    | 3. AuditFilter — write JSONL record
    |
    | Verdict:
    |   ALLOW -> forward to real server
    |   DENY  -> return JSON-RPC error
    |   ASK   -> queue for human approval (dashboard)
    |   LOG   -> allow but flag
    v
Real MCP Server (subprocess or remote HTTP)
    |
    v
Web Dashboard (http://127.0.0.1:8080)
    - Live audit log (SSE streaming)
    - Approval queue (approve/deny pending actions)
    - Policy viewer
    - Stats overview
    - SDK API (/api/v1/check, /api/v1/stats)
```

## CLI Commands

```bash
agentguard proxy -c policy.yaml -- <command>        # stdio proxy
agentguard httpproxy --target <url> --listen :3000   # HTTP proxy
agentguard serve -c policy.yaml -- <command>         # proxy + dashboard
agentguard dashboard -c policy.yaml                  # dashboard only
agentguard check -c policy.yaml --method <method>    # dry-run policy check
agentguard version                                   # print version
```

## Configuration

See [`configs/default.yaml`](configs/default.yaml) for the default deny policy and [`configs/permissive.yaml`](configs/permissive.yaml) for a logging-only policy.

## Roadmap

- [x] stdio MCP proxy
- [x] HTTP Streamable transport proxy
- [x] YAML first-match-wins policy engine
- [x] JSONL audit logging with rotation
- [x] Web dashboard with HTMX
- [x] Approval queue
- [x] CLI (proxy, httpproxy, serve, dashboard, check, version)
- [x] GitHub Actions CI/CD
- [x] goreleaser cross-platform binaries
- [x] OPA/Rego policy engine
- [x] Secret scanner filter (12 patterns + entropy analysis)
- [x] Rate limiting filter (per-tool + global sliding window)
- [x] Python SDK (LangChain, CrewAI integrations)

## License

Apache-2.0
