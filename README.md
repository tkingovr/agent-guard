# AgentGuard

**Open-source firewall and audit layer for AI agents.**

AgentGuard intercepts MCP (Model Context Protocol) tool calls, evaluates them against configurable policies, and provides real-time audit logging. It acts as a MITM proxy between AI hosts (Claude Desktop, Cursor, etc.) and MCP servers.

## Features

- **MCP stdio proxy** — sits between AI host and MCP server, inspecting every JSON-RPC message
- **YAML policy engine** — first-match-wins rules with method/tool/argument matching and regex support
- **Default-deny security** — blocks everything not explicitly allowed
- **Audit logging** — JSONL append-only logs with date-based rotation
- **Approval queue** — `ask` verdict pauses execution for human approval
- **CLI dry-run** — test policies without running the proxy
- **4 verdicts** — `allow`, `deny`, `ask`, `log`

## Quick Start

```bash
# Build
make build

# Test a policy rule (dry-run)
./bin/agentguard check -c configs/default.yaml --method tools/call --tool read_file --args '{"path":"/tmp/test"}'

# Run the proxy
./bin/agentguard proxy -c configs/default.yaml -- npx @modelcontextprotocol/server-filesystem ~/projects
```

## Policy Example

```yaml
version: 1
settings:
  default_action: deny

rules:
  - name: allow-initialize
    match:
      method: "initialize"
    action: allow

  - name: block-ssh-keys
    match:
      method: "tools/call"
      arguments:
        _any_value:
          regex: "(\\.ssh/|id_rsa|id_ed25519)"
    action: deny
    message: "SSH key access blocked"

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
AgentGuard Proxy (stdin/stdout)
    |
    | Filter Chain:
    | 1. ParseFilter — extract method, tool, arguments
    | 2. PolicyFilter — evaluate YAML rules → verdict
    | 3. AuditFilter — write JSONL record
    |
    | Verdict:
    |   ALLOW → forward to real server
    |   DENY  → return JSON-RPC error
    |   ASK   → queue for human approval
    |   LOG   → allow but flag
    v
Real MCP Server (subprocess)
```

## CLI Commands

```bash
agentguard proxy -c policy.yaml -- <mcp-server-command>   # stdio proxy
agentguard check -c policy.yaml --method <method> [flags]  # dry-run policy check
agentguard version                                         # print version
```

## Configuration

See [`configs/default.yaml`](configs/default.yaml) for the default deny policy and [`configs/permissive.yaml`](configs/permissive.yaml) for a logging-only policy.

## Roadmap

- [ ] HTTP Streamable transport proxy
- [ ] Web dashboard (real-time audit, approval queue, policy viewer)
- [ ] OPA/Rego policy engine
- [ ] Secret scanner filter
- [ ] Rate limiting filter
- [ ] Python SDK (LangChain, CrewAI integrations)
- [ ] goreleaser cross-platform binaries

## License

Apache-2.0
