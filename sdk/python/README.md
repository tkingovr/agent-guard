# AgentGuard Python SDK

Python client for [AgentGuard](https://github.com/tkingovr/agent-guard) — firewall and audit layer for AI agents.

## Install

```bash
pip install agentguard

# With LangChain support
pip install agentguard[langchain]

# With CrewAI support
pip install agentguard[crewai]
```

## Quick Start

```python
from agentguard import AgentGuardClient

client = AgentGuardClient("http://127.0.0.1:8080")

# Check a tool call against policy
result = client.check(method="tools/call", tool="write_file", arguments={"path": "/tmp/test.txt"})
if result.denied:
    print(f"Blocked: {result.message}")
else:
    print(f"Allowed (rule: {result.rule})")

# Get audit stats
stats = client.stats()
print(f"Total: {stats.total_requests}, Denied: {stats.deny_count}")
```

## LangChain Integration

```python
from agentguard.langchain import AgentGuardCallbackHandler

handler = AgentGuardCallbackHandler("http://127.0.0.1:8080")
agent = initialize_agent(tools, llm, callbacks=[handler])
# Tool calls are now checked against AgentGuard policy
```

## CrewAI Integration

```python
from agentguard.crewai import agentguard_step_callback

crew = Crew(
    agents=[...],
    tasks=[...],
    step_callback=agentguard_step_callback("http://127.0.0.1:8080"),
)
```

## @guard Decorator

```python
from agentguard.decorator import guard, configure

configure("http://127.0.0.1:8080")

@guard(tool="write_file")
def write_file(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)

write_file("/tmp/test.txt", "hello")  # Checked against policy first
```

## Async Support

```python
from agentguard.client import AsyncAgentGuardClient

async with AsyncAgentGuardClient("http://127.0.0.1:8080") as client:
    result = await client.check(method="tools/call", tool="read_file")
```

## License

Apache-2.0
