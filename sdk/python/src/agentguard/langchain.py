"""LangChain callback handler for AgentGuard policy enforcement.

Usage::

    from agentguard.langchain import AgentGuardCallbackHandler

    handler = AgentGuardCallbackHandler("http://127.0.0.1:8080")
    agent = initialize_agent(..., callbacks=[handler])
"""

from __future__ import annotations

import logging
from typing import Any

from agentguard.client import AgentGuardClient

logger = logging.getLogger("agentguard.langchain")

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError(
        "langchain-core is required for LangChain integration. "
        "Install it with: pip install agentguard[langchain]"
    )


class AgentGuardCallbackHandler(BaseCallbackHandler):
    """LangChain callback that checks tool calls against AgentGuard policy.

    Raises ``PermissionError`` when a tool call is denied by policy.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        *,
        raise_on_deny: bool = True,
        timeout: float = 10.0,
    ) -> None:
        self.client = AgentGuardClient(base_url, timeout=timeout)
        self.raise_on_deny = raise_on_deny

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running. Checks policy before execution."""
        tool_name = serialized.get("name", kwargs.get("name", ""))

        # Build arguments from input
        arguments: dict[str, Any] = {}
        if isinstance(input_str, str):
            arguments["input"] = input_str
        # Also include any tool_input from kwargs
        tool_input = kwargs.get("tool_input")
        if isinstance(tool_input, dict):
            arguments.update(tool_input)

        result = self.client.check(
            method="tools/call",
            tool=tool_name,
            arguments=arguments if arguments else None,
        )

        if result.denied:
            msg = f"AgentGuard denied tool '{tool_name}': {result.message} (rule: {result.rule})"
            logger.warning(msg)
            if self.raise_on_deny:
                raise PermissionError(msg)
        elif result.verdict == "ask":
            msg = f"AgentGuard requires approval for tool '{tool_name}': {result.message}"
            logger.info(msg)
        else:
            logger.debug(f"AgentGuard allowed tool '{tool_name}' (rule: {result.rule})")
