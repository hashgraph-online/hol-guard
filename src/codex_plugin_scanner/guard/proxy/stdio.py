"""Local stdio MCP proxy helpers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..approvals import queue_blocked_approvals
from ..consumer import artifact_hash
from ..models import HarnessDetection
from ..receipts import build_receipt
from ..runtime.secret_file_requests import build_file_read_request_artifact, extract_sensitive_file_read_request
from ..store import GuardStore


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


def _blocked_tool_response(message_id: Any, tool_name: str, reason: str | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32001,
            "message": reason or f"Guard blocked tool call for {tool_name}.",
        },
    }


class StdioGuardProxy:
    """Proxy JSON-RPC traffic to a stdio subprocess while recording metadata-only events."""

    def __init__(
        self,
        command: list[str],
        blocked_tools: set[str] | None = None,
        cwd: Path | None = None,
        guard_store: GuardStore | None = None,
        guard_config: object | None = None,
        approval_center_url: str | None = None,
        harness: str = "guard-proxy",
    ) -> None:
        self.command = command
        self.blocked_tools = blocked_tools or set()
        self.cwd = cwd
        self.guard_store = guard_store
        self.guard_config = guard_config
        self.approval_center_url = approval_center_url
        self.harness = harness

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
                if method == "tools/call" and tool_name is not None:
                    sensitive_request = extract_sensitive_file_read_request(
                        tool_name,
                        params.get("arguments") if isinstance(params, dict) else None,
                        cwd=self.cwd,
                    )
                    if sensitive_request is not None:
                        runtime_artifact = build_file_read_request_artifact(
                            harness=self.harness,
                            request=sensitive_request,
                            config_path=str(self._policy_path()),
                            source_scope="project" if self.cwd is not None else "global",
                        )
                        runtime_artifact_hash = artifact_hash(runtime_artifact)
                        policy_action = (
                            self.guard_store.resolve_policy(
                                self.harness,
                                runtime_artifact.artifact_id,
                                runtime_artifact_hash,
                                str(self.cwd) if self.cwd is not None else None,
                            )
                            if self.guard_store is not None
                            else None
                        )
                        if not isinstance(policy_action, str):
                            policy_action = "require-reapproval"
                        event["artifact_id"] = runtime_artifact.artifact_id
                        event["artifact_type"] = runtime_artifact.artifact_type
                        event["path_summary"] = sensitive_request.path_match.normalized_path
                        event["risk_summary"] = runtime_artifact.metadata.get("runtime_request_summary")
                        if self.guard_store is not None:
                            self.guard_store.add_receipt(
                                build_receipt(
                                    harness=self.harness,
                                    artifact_id=runtime_artifact.artifact_id,
                                    artifact_hash=runtime_artifact_hash,
                                    policy_decision=policy_action,
                                    capabilities_summary=f"file read request • {sensitive_request.tool_name}",
                                    changed_capabilities=["file_read_request"],
                                    provenance_summary=f"runtime MCP tool request evaluated from {self._policy_path()}",
                                    artifact_name=runtime_artifact.name,
                                    source_scope=runtime_artifact.source_scope,
                                )
                            )
                        if policy_action in {"block", "sandbox-required", "require-reapproval"}:
                            event["decision"] = "block"
                            if self.guard_store is not None and self.approval_center_url is not None:
                                event["approval_requests"] = queue_blocked_approvals(
                                    detection=HarnessDetection(
                                        harness=self.harness,
                                        installed=True,
                                        command_available=True,
                                        config_paths=(runtime_artifact.config_path,),
                                        artifacts=(runtime_artifact,),
                                    ),
                                    evaluation={
                                        "artifacts": [
                                            {
                                                "artifact_id": runtime_artifact.artifact_id,
                                                "artifact_name": runtime_artifact.name,
                                                "artifact_hash": runtime_artifact_hash,
                                                "policy_action": policy_action,
                                                "changed_fields": ["file_read_request"],
                                                "artifact_type": runtime_artifact.artifact_type,
                                                "source_scope": runtime_artifact.source_scope,
                                                "config_path": runtime_artifact.config_path,
                                                "launch_target": runtime_artifact.metadata.get("request_summary"),
                                            }
                                        ]
                                    },
                                    store=self.guard_store,
                                    approval_center_url=self.approval_center_url,
                                )
                            events.append(event)
                            responses.append(
                                _blocked_tool_response(
                                    message.get("id"),
                                    tool_name,
                                    f"Guard blocked sensitive local file access for {tool_name}: "
                                    f"{sensitive_request.path_match.path_class}.",
                                )
                            )
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

    def _policy_path(self) -> Path:
        if self.cwd is not None:
            return self.cwd / ".mcp.json"
        return Path.home() / ".mcp.json"
