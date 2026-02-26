"""CrewAI integration for AgentGuard policy enforcement.

Usage::

    from agentguard.crewai import agentguard_step_callback

    crew = Crew(
        agents=[...],
        tasks=[...],
        step_callback=agentguard_step_callback("http://127.0.0.1:8080"),
    )
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from agentguard.client import AgentGuardClient

logger = logging.getLogger("agentguard.crewai")


def agentguard_step_callback(
    base_url: str = "http://127.0.0.1:8080",
    *,
    raise_on_deny: bool = True,
    timeout: float = 10.0,
) -> Callable[[Any], None]:
    """Create a CrewAI step callback that enforces AgentGuard policies.

    Args:
        base_url: AgentGuard dashboard URL.
        raise_on_deny: Raise PermissionError on deny verdict.
        timeout: HTTP request timeout in seconds.

    Returns:
        A callback function suitable for CrewAI's ``step_callback``.
    """
    client = AgentGuardClient(base_url, timeout=timeout)

    def callback(step_output: Any) -> None:
        # CrewAI step_output varies by version; extract tool info if available
        tool_name = ""
        arguments: dict[str, Any] = {}

        if hasattr(step_output, "tool"):
            tool_name = str(step_output.tool)
        if hasattr(step_output, "tool_input"):
            tool_input = step_output.tool_input
            if isinstance(tool_input, dict):
                arguments = tool_input
            elif isinstance(tool_input, str):
                arguments = {"input": tool_input}

        # Skip steps without tool calls
        if not tool_name:
            return

        result = client.check(
            method="tools/call",
            tool=tool_name,
            arguments=arguments if arguments else None,
        )

        if result.denied:
            msg = f"AgentGuard denied tool '{tool_name}': {result.message} (rule: {result.rule})"
            logger.warning(msg)
            if raise_on_deny:
                raise PermissionError(msg)
        elif result.verdict == "ask":
            logger.info(f"AgentGuard requires approval for tool '{tool_name}': {result.message}")
        else:
            logger.debug(f"AgentGuard allowed tool '{tool_name}' (rule: {result.rule})")

    return callback
