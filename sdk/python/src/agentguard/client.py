"""HTTP client for the AgentGuard API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class CheckResult:
    """Result of a policy check."""

    verdict: str
    rule: str = ""
    message: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict in ("allow", "log")

    @property
    def denied(self) -> bool:
        return self.verdict == "deny"


@dataclass
class AuditStats:
    """Audit statistics from the AgentGuard dashboard."""

    total_requests: int = 0
    allow_count: int = 0
    deny_count: int = 0
    ask_count: int = 0
    log_count: int = 0
    by_method: dict[str, int] = field(default_factory=dict)
    by_tool: dict[str, int] = field(default_factory=dict)


class AgentGuardClient:
    """Synchronous HTTP client for the AgentGuard API.

    Usage::

        client = AgentGuardClient("http://127.0.0.1:8080")
        result = client.check(method="tools/call", tool="write_file", arguments={"path": "/tmp/x"})
        if result.denied:
            raise RuntimeError(f"Blocked by policy: {result.message}")
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080", *, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=timeout)

    def check(
        self,
        method: str,
        tool: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Evaluate a tool call against the AgentGuard policy.

        Args:
            method: JSON-RPC method (e.g. "tools/call").
            tool: Tool name (e.g. "write_file").
            arguments: Tool arguments dict.

        Returns:
            CheckResult with verdict, rule, and message.

        Raises:
            httpx.HTTPStatusError: On non-2xx responses.
        """
        payload: dict[str, Any] = {"method": method}
        if tool:
            payload["tool"] = tool
        if arguments:
            payload["arguments"] = arguments

        resp = self._client.post("/api/v1/check", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return CheckResult(
            verdict=data.get("verdict", "deny"),
            rule=data.get("rule", ""),
            message=data.get("message", ""),
        )

    def stats(self) -> AuditStats:
        """Fetch audit statistics from the AgentGuard dashboard.

        Returns:
            AuditStats with counts and breakdowns.
        """
        resp = self._client.get("/api/v1/stats")
        resp.raise_for_status()
        data = resp.json()
        return AuditStats(
            total_requests=data.get("total_requests", 0),
            allow_count=data.get("allow_count", 0),
            deny_count=data.get("deny_count", 0),
            ask_count=data.get("ask_count", 0),
            log_count=data.get("log_count", 0),
            by_method=data.get("by_method") or {},
            by_tool=data.get("by_tool") or {},
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> AgentGuardClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncAgentGuardClient:
    """Async HTTP client for the AgentGuard API.

    Usage::

        async with AsyncAgentGuardClient("http://127.0.0.1:8080") as client:
            result = await client.check(method="tools/call", tool="write_file")
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8080", *, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=timeout)

    async def check(
        self,
        method: str,
        tool: str = "",
        arguments: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Evaluate a tool call against the AgentGuard policy (async)."""
        payload: dict[str, Any] = {"method": method}
        if tool:
            payload["tool"] = tool
        if arguments:
            payload["arguments"] = arguments

        resp = await self._client.post("/api/v1/check", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return CheckResult(
            verdict=data.get("verdict", "deny"),
            rule=data.get("rule", ""),
            message=data.get("message", ""),
        )

    async def stats(self) -> AuditStats:
        """Fetch audit statistics (async)."""
        resp = await self._client.get("/api/v1/stats")
        resp.raise_for_status()
        data = resp.json()
        return AuditStats(
            total_requests=data.get("total_requests", 0),
            allow_count=data.get("allow_count", 0),
            deny_count=data.get("deny_count", 0),
            ask_count=data.get("ask_count", 0),
            log_count=data.get("log_count", 0),
            by_method=data.get("by_method") or {},
            by_tool=data.get("by_tool") or {},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncAgentGuardClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
