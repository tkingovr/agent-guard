"""Tests for the @guard decorator."""

import pytest
import httpx
import respx

from agentguard.client import AgentGuardClient
from agentguard.decorator import guard, configure, _get_client


class TestGuardDecorator:
    @respx.mock
    def test_allow_passes_through(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={"verdict": "allow", "rule": "ok"})
        )

        client = AgentGuardClient("http://localhost:8080")

        @guard(tool="read_file", client=client)
        def read_file(path: str) -> str:
            return f"content of {path}"

        result = read_file("/tmp/test.txt")
        assert result == "content of /tmp/test.txt"

    @respx.mock
    def test_deny_raises(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={
                "verdict": "deny",
                "rule": "block-ssh",
                "message": "SSH blocked",
            })
        )

        client = AgentGuardClient("http://localhost:8080")

        @guard(tool="read_file", client=client)
        def read_file(path: str) -> str:
            return "should not reach here"

        with pytest.raises(PermissionError, match="SSH blocked"):
            read_file("/home/user/.ssh/id_rsa")

    @respx.mock
    def test_deny_no_raise(self):
        respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={
                "verdict": "deny",
                "rule": "block",
                "message": "nope",
            })
        )

        client = AgentGuardClient("http://localhost:8080")

        @guard(tool="write_file", client=client, raise_on_deny=False)
        def write_file(path: str, content: str) -> str:
            return "written"

        result = write_file("/etc/passwd", "hacked")
        assert result is None  # Returns None instead of raising

    @respx.mock
    def test_uses_function_name_as_tool(self):
        route = respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={"verdict": "allow"})
        )

        client = AgentGuardClient("http://localhost:8080")

        @guard(client=client)
        def my_custom_tool(x: int) -> int:
            return x * 2

        my_custom_tool(5)

        body = route.calls[0].request.content.decode()
        assert "my_custom_tool" in body

    @respx.mock
    def test_arguments_captured(self):
        route = respx.post("http://localhost:8080/api/v1/check").mock(
            return_value=httpx.Response(200, json={"verdict": "allow"})
        )

        client = AgentGuardClient("http://localhost:8080")

        @guard(tool="write_file", client=client)
        def write_file(path: str, content: str) -> None:
            pass

        write_file("/tmp/out.txt", "hello world")

        import json
        body = json.loads(route.calls[0].request.content)
        assert body["arguments"]["path"] == "/tmp/out.txt"
        assert body["arguments"]["content"] == "hello world"
