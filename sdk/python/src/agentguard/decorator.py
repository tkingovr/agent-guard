"""Generic @guard decorator for AgentGuard policy enforcement.

Usage::

    from agentguard.decorator import guard

    @guard(tool="write_file")
    def write_file(path: str, content: str) -> None:
        ...

    # Or with explicit arguments mapping:
    @guard(tool="run_command", args_from="kwargs")
    def run_command(**kwargs):
        ...
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, TypeVar

from agentguard.client import AgentGuardClient

logger = logging.getLogger("agentguard.decorator")

F = TypeVar("F", bound=Callable[..., Any])

# Module-level default client (lazily initialized)
_default_client: AgentGuardClient | None = None


def configure(base_url: str = "http://127.0.0.1:8080", *, timeout: float = 10.0) -> None:
    """Configure the default AgentGuard client used by @guard decorators.

    Call this once at application startup::

        import agentguard.decorator
        agentguard.decorator.configure("http://localhost:8080")
    """
    global _default_client
    _default_client = AgentGuardClient(base_url, timeout=timeout)


def _get_client() -> AgentGuardClient:
    global _default_client
    if _default_client is None:
        _default_client = AgentGuardClient()
    return _default_client


def guard(
    tool: str = "",
    *,
    method: str = "tools/call",
    client: AgentGuardClient | None = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """Decorator that checks AgentGuard policy before function execution.

    Args:
        tool: Tool name for the policy check. Defaults to the function name.
        method: JSON-RPC method. Defaults to "tools/call".
        client: Optional explicit AgentGuardClient. Uses default if not set.
        raise_on_deny: Raise PermissionError on deny. Default True.

    Returns:
        Decorated function.
    """

    def decorator(func: F) -> F:
        resolved_tool = tool or func.__name__
        sig = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Build arguments from function call
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)

            c = client or _get_client()
            result = c.check(
                method=method,
                tool=resolved_tool,
                arguments=arguments if arguments else None,
            )

            if result.denied:
                msg = f"AgentGuard denied '{resolved_tool}': {result.message} (rule: {result.rule})"
                logger.warning(msg)
                if raise_on_deny:
                    raise PermissionError(msg)
                return None

            if result.verdict == "ask":
                logger.info(
                    f"AgentGuard requires approval for '{resolved_tool}': {result.message}"
                )

            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
