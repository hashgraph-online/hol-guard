"""Local stdio MCP proxy helpers."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..approvals import approval_delivery_payload, approval_prompt_flow, queue_blocked_approvals
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


def _blocked_tool_response(
    message_id: Any,
    tool_name: str,
    reason: str | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32001,
            "message": reason or f"Guard blocked tool call for {tool_name}.",
        },
    }
    if data:
        payload["error"]["data"] = data
    return payload


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
        env: dict[str, str] | None = None,
    ) -> None:
        self.command = command
        self.blocked_tools = blocked_tools or set()
        self.cwd = cwd
        self.guard_store = guard_store
        self.guard_config = guard_config
        self.approval_center_url = approval_center_url
        self.harness = harness
        self.env = env or {}

    def run_session(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        responses, events, return_code = self._run_messages(messages)
        return {
            "command": self.command,
            "events": events,
            "responses": responses,
            "return_code": return_code,
        }

    def run_stream(self, *, input_stream: Any, output_stream: Any, error_stream: Any) -> int:
        process = self._start_process()

        try:
            for raw_line in input_stream:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"Guard stdio proxy received invalid JSON: {exc}", file=error_stream)
                    return 2
                response = self._forward_message(
                    process=process,
                    message=message,
                    responses=[],
                    events=[],
                    output_stream=output_stream,
                )
                if response is not None:
                    output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
                    output_stream.flush()
            assert process.stdin is not None
            process.stdin.close()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        return process.returncode if isinstance(process.returncode, int) else 0

    def _run_messages(
        self, messages: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int | None]:
        process = self._start_process()
        responses: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []

        try:
            for message in messages:
                self._forward_message(
                    process=process,
                    message=message,
                    responses=responses,
                    events=events,
                    output_stream=None,
                )
            assert process.stdin is not None
            process.stdin.close()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        return responses, events, process.returncode

    def _start_process(self) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            cwd=self.cwd,
            env={**os.environ, **self.env},
        )

    def _forward_message(
        self,
        *,
        process: subprocess.Popen[str],
        message: dict[str, Any],
        responses: list[dict[str, Any]],
        events: list[dict[str, Any]],
        output_stream: Any | None = None,
    ) -> dict[str, Any] | None:
        assert process.stdin is not None
        assert process.stdout is not None

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
            response = _blocked_tool_response(message.get("id"), tool_name)
            events.append(event)
            responses.append(response)
            return response
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
                    blocked_message = (
                        f"Guard blocked sensitive local file access for {tool_name}: "
                        f"{sensitive_request.path_match.path_class}."
                    )
                    response_data = None
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
                        managed_install = self.guard_store.get_managed_install(self.harness)
                        approval_flow = approval_prompt_flow(
                            self.harness,
                            managed_install=managed_install,
                        )
                        event["approval_center_url"] = self.approval_center_url
                        event["approval_delivery"] = approval_delivery_payload(approval_flow)
                        event["review_hint"] = (
                            f"{approval_flow['summary']} Open {self.approval_center_url} to review the blocked request."
                        )
                        blocked_message = f"{blocked_message} {event['review_hint']}"
                        response_data = {
                            "approvalCenterUrl": self.approval_center_url,
                            "approvalRequests": event["approval_requests"],
                            "approvalDelivery": event["approval_delivery"],
                            "reviewHint": event["review_hint"],
                        }
                    response = _blocked_tool_response(
                        message.get("id"),
                        tool_name,
                        blocked_message,
                        response_data,
                    )
                    events.append(event)
                    responses.append(response)
                    return response

        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        response = self._read_response(
            process=process,
            message_id=message.get("id"),
            output_stream=output_stream,
        )
        if response is None:
            return None
        responses.append(response)
        events.append(event)
        return response

    def _read_response(
        self,
        *,
        process: subprocess.Popen[str],
        message_id: Any,
        output_stream: Any | None = None,
    ) -> dict[str, Any] | None:
        if message_id is None:
            return None
        assert process.stdout is not None
        while True:
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("Guard stdio proxy did not receive a response from the MCP server.")
            response = json.loads(line)
            if response.get("id") == message_id:
                return response
            if output_stream is not None:
                output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
                output_stream.flush()

    def _policy_path(self) -> Path:
        if self.cwd is not None:
            return self.cwd / ".mcp.json"
        return Path.home() / ".mcp.json"


def _is_notification(message: dict[str, Any]) -> bool:
    return "method" in message and "id" not in message


def _is_request(message: dict[str, Any]) -> bool:
    return "method" in message and "id" in message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
