"""Local stdio MCP proxy helpers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _redact_scalar(value: str) -> str:
    lower_value = value.lower()
    if any(token in lower_value for token in ("authorization", "api-key", "bearer ", "token", "secret")):
        return "*****"
    return value


def _redact_json(value: Any) -> Any:
    if isinstance(value, str):
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc and parsed.query:
            pairs = []
            for key, item in parse_qsl(parsed.query, keep_blank_values=True):
                if any(token in key.lower() for token in ("key", "token", "auth", "secret")):
                    pairs.append((key, "*****"))
                    continue
                pairs.append((key, item))
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), parsed.fragment))
        return _redact_scalar(value)
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if any(token in key.lower() for token in ("authorization", "api-key", "token", "secret")):
                redacted[key] = "*****"
                continue
            redacted[str(key)] = _redact_json(item)
        return redacted
    return value


def _blocked_tool_response(message_id: Any, tool_name: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32001,
            "message": f"Guard blocked tool call for {tool_name}.",
        },
    }


class StdioGuardProxy:
    """Proxy JSON-RPC traffic to a stdio subprocess while recording metadata-only events."""

    def __init__(
        self,
        command: list[str],
        blocked_tools: set[str] | None = None,
        cwd: Path | None = None,
    ) -> None:
        self.command = command
        self.blocked_tools = blocked_tools or set()
        self.cwd = cwd

    def run_session(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=self.cwd,
        )
        responses: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []

        try:
            assert process.stdin is not None
            assert process.stdout is not None

            for message in messages:
                method = str(message.get("method", "unknown"))
                params = message.get("params", {})
                tool_name = None
                if isinstance(params, dict):
                    raw_tool_name = params.get("name")
                    tool_name = raw_tool_name if isinstance(raw_tool_name, str) else None

                event = {
                    "method": method,
                    "tool_name": tool_name,
                    "decision": "forward",
                    "redacted_params": _redact_json(params),
                }

                if method == "tools/call" and tool_name in self.blocked_tools:
                    event["decision"] = "block"
                    events.append(event)
                    responses.append(_blocked_tool_response(message.get("id"), tool_name))
                    continue

                process.stdin.write(json.dumps(message) + "\n")
                process.stdin.flush()
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError("Guard stdio proxy did not receive a response from the MCP server.")
                responses.append(json.loads(line))
                events.append(event)

            process.stdin.close()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

        return {
            "command": self.command,
            "events": events,
            "responses": responses,
            "return_code": process.returncode,
        }
