"""Tests for the AgentGuard Python SDK client."""

import pytest
import httpx
import respx

from agentguard.client import AgentGuardClient, AsyncAgentGuardClient, CheckResult, AuditStats


class TestCheckResult:
    def test_allowed_for_allow(self):
        r = CheckResult(verdict="allow", rule="allow-read")
        assert r.allowed is True
        assert r.denied is False

    def test_allowed_for_log(self):
        r = CheckResult(verdict="log", rule="log-all")
        assert r.allowed is True
        assert r.denied is False

    def test_denied_for_deny(self):
        r = CheckResult(verdict="deny", rule="block-ssh", message="SSH blocked")
        assert r.denied is True
        assert r.allowed is False

    def test_ask_is_not_allowed(self):
        r = CheckResult(verdict="ask")
        assert r.allowed is False
        assert r.denied is False


class TestAgentGuardClient:
    @respx.mock
    def test_check_allow(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={
                "verdict": "allow",
                "rule": "allow-read-file",
                "message": "",
            })
        )

        with AgentGuardClient("http://localhost:8080") as client:
            result = client.check(method="tools/call", tool="read_file")

        assert result.verdict == "allow"
        assert result.rule == "allow-read-file"
        assert result.allowed is True

    @respx.mock
    def test_check_deny(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={
                "verdict": "deny",
                "rule": "block-ssh-keys",
                "message": "SSH key access blocked",
            })
        )

        with AgentGuardClient("http://localhost:8080") as client:
            result = client.check(
                method="tools/call",
                tool="read_file",
                arguments={"path": "/home/user/.ssh/id_rsa"},
            )

        assert result.denied is True
        assert result.rule == "block-ssh-keys"
        assert result.message == "SSH key access blocked"

    @respx.mock
    def test_check_with_arguments(self):
        route = respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={"verdict": "allow", "rule": "ok"})
        )

        with AgentGuardClient("http://localhost:8080") as client:
            client.check(
                method="tools/call",
                tool="write_file",
                arguments={"path": "/tmp/test.txt", "content": "hello"},
            )

        request = route.calls[0].request
        body = request.content.decode()
        assert '"tool":"write_file"' in body.replace(" ", "")
        assert '"path"' in body

    @respx.mock
    def test_check_minimal(self):
        """Check with only method set."""
        route = respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={"verdict": "allow"})
        )

        with AgentGuardClient("http://localhost:8080") as client:
            result = client.check(method="initialize")

        assert result.verdict == "allow"
        # tool and arguments should not be in request body
        body = route.calls[0].request.content.decode()
        assert "tool" not in body

    @respx.mock
    def test_stats(self):
        respx.get("http://localhost:8080/api/v1/stats").mock(
            return_value=httpx.Response(200, json={
                "total_requests": 150,
                "allow_count": 100,
                "deny_count": 30,
                "ask_count": 10,
                "log_count": 10,
                "by_method": {"tools/call": 120, "initialize": 30},
                "by_tool": {"read_file": 80, "write_file": 40},
            })
        )

        with AgentGuardClient("http://localhost:8080") as client:
            stats = client.stats()

        assert stats.total_requests == 150
        assert stats.allow_count == 100
        assert stats.deny_count == 30
        assert stats.by_method["tools/call"] == 120
        assert stats.by_tool["write_file"] == 40

    @respx.mock
    def test_stats_empty(self):
        respx.get("http://localhost:8080/api/v1/stats").mock(
            return_value=httpx.Response(200, json={
                "total_requests": 0,
                "allow_count": 0,
                "deny_count": 0,
                "ask_count": 0,
                "log_count": 0,
            })
        )

        with AgentGuardClient("http://localhost:8080") as client:
            stats = client.stats()

        assert stats.total_requests == 0
        assert stats.by_method == {}
        assert stats.by_tool == {}

    @respx.mock
    def test_http_error_raises(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(500, text="internal error")
        )

        with AgentGuardClient("http://localhost:8080") as client:
            with pytest.raises(httpx.HTTPStatusError):
                client.check(method="tools/call", tool="bad")

    @respx.mock
    def test_trailing_slash_stripped(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={"verdict": "allow"})
        )

        with AgentGuardClient("http://localhost:8080/") as client:
            result = client.check(method="initialize")
        assert result.allowed


@pytest.mark.asyncio
class TestAsyncAgentGuardClient:
    @respx.mock
    async def test_check(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={
                "verdict": "deny",
                "rule": "block-ssh",
                "message": "blocked",
            })
        )

        async with AsyncAgentGuardClient("http://localhost:8080") as client:
            result = await client.check(method="tools/call", tool="read_file")

        assert result.denied is True

    @respx.mock
    async def test_stats(self):
        respx.get("http://localhost:8080/api/v1/stats").mock(
            return_value=httpx.Response(200, json={
                "total_requests": 42,
                "allow_count": 42,
                "deny_count": 0,
                "ask_count": 0,
                "log_count": 0,
            })
        )

        async with AsyncAgentGuardClient("http://localhost:8080") as client:
            stats = await client.stats()

        assert stats.total_requests == 42
