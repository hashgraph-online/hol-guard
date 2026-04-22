"""Runtime MCP proxy implementations used by managed harness adapters."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, TextIO

from ..adapters.base import HarnessContext
from ..approvals import queue_blocked_approvals
from ..config import GuardConfig
from ..daemon import ensure_guard_daemon
from ..mcp_tool_calls import (
    allow_tool_call,
    block_tool_call,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
    tool_call_risk_summary,
)
from ..models import HarnessDetection
from ..store import GuardStore
from .stdio import _blocked_tool_response, _redact_json


class RuntimeMcpGuardProxy:
    """Guard-managed MCP proxy for harnesses that talk stdio MCP to local servers."""

    def __init__(
        self,
        *,
        harness: str,
        server_name: str,
        command: list[str],
        context: HarnessContext,
        store: GuardStore,
        config: GuardConfig,
        source_scope: str,
        config_path: str,
        transport: str = "stdio",
    ) -> None:
        self.harness = harness
        self.server_name = server_name
        self.command = command
        self.context = context
        self.store = store
        self.config = config
        self.source_scope = source_scope
        self.config_path = config_path
        self.transport = transport
        self._inline_prompt_available = False
        self._inline_prompt_counter = 0
        self._buffered_child_responses: dict[str, list[dict[str, Any]]] = {}
        self._buffered_client_responses: dict[str, list[dict[str, Any]]] = {}

    def run_session(
        self,
        messages: list[dict[str, Any]],
        *,
        inline_approval_callback: Any | None = None,
    ) -> dict[str, Any]:
        process = self._start_process()
        responses: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            for message in messages:
                response, event = self._handle_message(
                    message=message,
                    child_stdin=process.stdin,
                    child_stdout=process.stdout,
                    client_input=None,
                    server_output=None,
                    approval_callback=inline_approval_callback,
                )
                if response is not None:
                    responses.append(response)
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

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
        input_stream = stdin or sys.stdin
        output_stream = stdout or sys.stdout
        process = self._start_process()
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            while True:
                line = input_stream.readline()
                if not line:
                    break
                message = json.loads(line)
                response, _ = self._handle_message(
                    message=message,
                    child_stdin=process.stdin,
                    child_stdout=process.stdout,
                    client_input=input_stream,
                    server_output=output_stream,
                    approval_callback=lambda request: self._request_inline_approval(
                        request,
                        input_stream=input_stream,
                        output_stream=output_stream,
                        child_stdin=process.stdin,
                        child_stdout=process.stdout,
                    ),
                )
                if response is not None:
                    output_stream.write(json.dumps(response) + "\n")
                    output_stream.flush()
            process.stdin.close()
            process.wait(timeout=5)
            return int(process.returncode or 0)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def _start_process(self) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            cwd=self.context.workspace_dir,
        )

    def _handle_message(
        self,
        *,
        message: dict[str, Any],
        child_stdin: TextIO,
        child_stdout: TextIO,
        client_input: TextIO | None,
        server_output: TextIO | None,
        approval_callback: Any | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        method = str(message.get("method", "unknown"))
        params = message.get("params", {})
        self._record_client_capabilities(method, params)
        event = {
            "method": method,
            "tool_name": params.get("name") if isinstance(params, dict) else None,
            "decision": "forward",
            "redacted_params": _redact_json(params),
        }
        if _is_notification(message):
            self._forward_notification(message, child_stdin)
            event["decision"] = "forward-notification"
            return None, event
        if not _is_request(message):
            self._forward_notification(message, child_stdin)
            event["decision"] = "forward-response"
            return None, event
        if method != "tools/call" or not isinstance(params, dict):
            response = self._forward_message(
                message,
                child_stdin,
                child_stdout,
                client_input=client_input,
                server_output=server_output,
            )
            return response, event

        tool_name = str(params.get("name") or "unknown")
        arguments = params.get("arguments")
        artifact = build_tool_call_artifact(
            harness=self.harness,
            server_name=self.server_name,
            tool_name=tool_name,
            source_scope=self.source_scope,
            config_path=self.config_path,
            transport=self.transport,
            server_fingerprint={
                "command": self.command,
                "transport": self.transport,
            },
        )
        artifact_hash = build_tool_call_hash(artifact, arguments)
        decision = evaluate_tool_call(
            store=self.store,
            config=self.config,
            artifact=artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
        )
        if decision.action == "allow" or (decision.source == "policy" and decision.action in {"warn", "review"}):
            return self._allow_and_forward(
                message=message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                artifact=artifact,
                artifact_hash=artifact_hash,
                decision_source=_decision_source(decision.action, decision.source),
                signals=decision.signals,
                params=params,
            )
        if self._allow_after_native_prompt(decision):
            return self._allow_and_forward(
                message=message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                artifact=artifact,
                artifact_hash=artifact_hash,
                decision_source="native-approved",
                signals=decision.signals,
                params=params,
            )
        if self._inline_prompt_available and approval_callback is not None:
            approval_result = approval_callback(self._inline_approval_request(tool_name, decision.summary))
            if _approval_allows(approval_result):
                return self._allow_and_forward(
                    message=message,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    decision_source="inline-approved",
                    signals=decision.signals,
                    params=params,
                    remember=True,
                )
            if _approval_denies(approval_result):
                block_tool_call(
                    store=self.store,
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    decision_source="inline-denied",
                    now=_now(),
                    signals=decision.signals,
                )
                return _blocked_tool_response(
                    message.get("id"),
                    tool_name,
                    f"HOL Guard blocked tool call {tool_name} from {self.server_name}.",
                ), {
                    **event,
                    "decision": "deny-inline",
                }
        response, queued_event = self._queue_approval_center_response(
            message_id=message.get("id"),
            artifact=artifact,
            artifact_hash=artifact_hash,
            tool_name=tool_name,
            signals=decision.signals,
            params=params,
        )
        return response, queued_event

    def _record_client_capabilities(self, method: str, params: object) -> None:
        del method, params

    def _allow_after_native_prompt(self, decision: object) -> bool:
        del decision
        return False

    def _inline_approval_request(self, tool_name: str, summary: str) -> dict[str, Any]:
        raise NotImplementedError

    def _allow_and_forward(
        self,
        *,
        message: dict[str, Any],
        child_stdin: TextIO,
        child_stdout: TextIO,
        client_input: TextIO | None,
        server_output: TextIO | None,
        artifact: Any,
        artifact_hash: str,
        decision_source: str,
        signals: tuple[str, ...],
        params: dict[str, Any],
        remember: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        allow_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source=decision_source,
            now=_now(),
            signals=signals,
            remember=remember,
        )
        response = self._forward_message(
            message,
            child_stdin,
            child_stdout,
            client_input=client_input,
            server_output=server_output,
        )
        return response, {
            "method": "tools/call",
            "tool_name": params.get("name"),
            "decision": decision_source,
            "redacted_params": _redact_json(params),
        }

    @staticmethod
    def _forward_notification(message: dict[str, Any], child_stdin: TextIO) -> None:
        child_stdin.write(json.dumps(message) + "\n")
        child_stdin.flush()

    def _forward_message(
        self,
        message: dict[str, Any],
        child_stdin: TextIO,
        child_stdout: TextIO,
        *,
        client_input: TextIO | None,
        server_output: TextIO | None,
    ) -> dict[str, Any]:
        request_id = message.get("id")
        child_stdin.write(json.dumps(message) + "\n")
        child_stdin.flush()
        while True:
            buffered_response = self._pop_buffered_child_response(request_id)
            if buffered_response is not None:
                return buffered_response
            line = child_stdout.readline()
            if not line:
                raise RuntimeError("Guard stdio proxy did not receive a response from the MCP server.")
            payload = json.loads(line)
            if payload.get("id") == request_id and not _is_request(payload):
                return payload
            if _is_request(payload):
                self._proxy_child_request(
                    payload=payload,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                )
                continue
            if "id" in payload:
                self._buffer_child_response(payload)
                continue
            if server_output is not None:
                server_output.write(json.dumps(payload) + "\n")
                server_output.flush()

    def _buffer_child_response(self, payload: dict[str, Any]) -> None:
        response_key = _response_key(payload.get("id"))
        if response_key is None:
            return
        self._buffered_child_responses.setdefault(response_key, []).append(payload)

    def _pop_buffered_child_response(self, request_id: Any) -> dict[str, Any] | None:
        response_key = _response_key(request_id)
        if response_key is None:
            return None
        pending = self._buffered_child_responses.get(response_key)
        if not pending:
            return None
        payload = pending.pop(0)
        if len(pending) == 0:
            self._buffered_child_responses.pop(response_key, None)
        return payload

    def _buffer_client_response(self, payload: dict[str, Any]) -> None:
        response_key = _response_key(payload.get("id"))
        if response_key is None:
            return
        self._buffered_client_responses.setdefault(response_key, []).append(payload)

    def _pop_buffered_client_response(self, request_id: Any) -> dict[str, Any] | None:
        response_key = _response_key(request_id)
        if response_key is None:
            return None
        pending = self._buffered_client_responses.get(response_key)
        if not pending:
            return None
        payload = pending.pop(0)
        if len(pending) == 0:
            self._buffered_client_responses.pop(response_key, None)
        return payload

    def _proxy_child_request(
        self,
        *,
        payload: dict[str, Any],
        child_stdin: TextIO,
        child_stdout: TextIO,
        client_input: TextIO | None,
        server_output: TextIO | None,
    ) -> None:
        if client_input is None or server_output is None:
            raise RuntimeError("Guard runtime MCP proxy cannot service nested child requests without a live client.")
        server_output.write(json.dumps(payload) + "\n")
        server_output.flush()
        request_id = payload.get("id")
        while True:
            buffered_response = self._pop_buffered_client_response(request_id)
            if buffered_response is not None:
                self._forward_notification(buffered_response, child_stdin)
                return
            line = client_input.readline()
            if not line:
                raise RuntimeError("Guard runtime MCP proxy lost the client while waiting for a server response.")
            message = json.loads(line)
            if message.get("id") == request_id and not _is_request(message):
                self._forward_notification(message, child_stdin)
                return
            if _is_notification(message):
                self._forward_notification(message, child_stdin)
                continue
            if not _is_request(message):
                self._buffer_client_response(message)
                continue
            response, _event = self._handle_message(
                message=message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                approval_callback=lambda approval_request: self._request_inline_approval(
                    approval_request,
                    input_stream=client_input,
                    output_stream=server_output,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                ),
            )
            if response is not None:
                server_output.write(json.dumps(response) + "\n")
                server_output.flush()

    def _request_inline_approval(
        self,
        request: dict[str, Any],
        *,
        input_stream: TextIO,
        output_stream: TextIO,
        child_stdin: TextIO,
        child_stdout: TextIO,
    ) -> dict[str, Any]:
        request_id = request.get("id")
        output_stream.write(json.dumps(request) + "\n")
        output_stream.flush()
        while True:
            buffered_response = self._pop_buffered_client_response(request_id)
            if buffered_response is not None:
                return _approval_payload(buffered_response)
            line = input_stream.readline()
            if not line:
                return {"action": "cancel"}
            payload = json.loads(line)
            if payload.get("id") == request_id and not _is_request(payload):
                return _approval_payload(payload)
            if _is_notification(payload):
                self._forward_notification(payload, child_stdin)
                continue
            if not _is_request(payload):
                self._buffer_client_response(payload)
                continue
            response, _event = self._handle_message(
                message=payload,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=input_stream,
                server_output=output_stream,
                approval_callback=lambda nested_request: self._request_inline_approval(
                    nested_request,
                    input_stream=input_stream,
                    output_stream=output_stream,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                ),
            )
            if response is not None:
                output_stream.write(json.dumps(response) + "\n")
                output_stream.flush()

    def _queue_approval_center_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        signals: tuple[str, ...],
        params: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        approval_center_url = ensure_guard_daemon(self.context.guard_home)
        queued = queue_blocked_approvals(
            detection=HarnessDetection(
                harness=self.harness,
                installed=True,
                command_available=True,
                config_paths=(self.config_path,),
                artifacts=(artifact,),
            ),
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": artifact_hash,
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "launch_target": self._launch_target(tool_name, params.get("arguments")),
                        "risk_summary": tool_call_risk_summary(artifact, params.get("arguments")),
                        "risk_signals": list(signals),
                    }
                ]
            },
            store=self.store,
            approval_center_url=approval_center_url,
            now=_now(),
        )
        block_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source="approval-center-pending",
            now=_now(),
            signals=signals,
        )
        request_id = str(queued[0]["request_id"]) if queued else "unknown"
        return _blocked_tool_response(
            message_id,
            tool_name,
            (
                f"HOL Guard stopped tool call {tool_name} from {self.server_name}. "
                f"Approve request {request_id} at {approval_center_url}, then retry the same action."
            ),
        ), {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "queue-approval",
            "redacted_params": _redact_json(params),
        }

    @staticmethod
    def _launch_target(tool_name: str, arguments: object) -> str:
        serialized_arguments = json.dumps(arguments) if arguments is not None else ""
        return f"{tool_name} {serialized_arguments}".strip()


class ElicitationMcpGuardProxy(RuntimeMcpGuardProxy):
    """Runtime MCP proxy that can ask for in-band approval via elicitation."""

    def _record_client_capabilities(self, method: str, params: object) -> None:
        if method != "initialize" or not isinstance(params, dict):
            return
        capabilities = params.get("capabilities")
        self._inline_prompt_available = bool(
            isinstance(capabilities, dict) and isinstance(capabilities.get("elicitation"), dict)
        )

    def _inline_approval_request(self, tool_name: str, summary: str) -> dict[str, Any]:
        self._inline_prompt_counter += 1
        return {
            "jsonrpc": "2.0",
            "id": f"guard-elicitation-{self._inline_prompt_counter}",
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": (
                    f"HOL Guard intercepted {self.server_name}.{tool_name}. {summary} Approve this exact call?"
                ),
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "decision": {
                            "type": "string",
                            "enum": ["approve", "deny"],
                            "enumNames": ["Approve", "Deny"],
                            "description": "Approve or reject this exact tool call.",
                        }
                    },
                    "required": ["decision"],
                },
            },
        }


class CodexMcpGuardProxy(ElicitationMcpGuardProxy):
    """Guard-managed runtime MCP proxy for Codex."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(harness="codex", **kwargs)


class CopilotMcpGuardProxy(ElicitationMcpGuardProxy):
    """Guard-managed runtime MCP proxy for Copilot MCP clients that support elicitation."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(harness="copilot", **kwargs)


class OpenCodeMcpGuardProxy(RuntimeMcpGuardProxy):
    """Guard-managed runtime MCP proxy for OpenCode."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(harness="opencode", **kwargs)

    def _allow_after_native_prompt(self, decision: Any) -> bool:
        return getattr(decision, "source", None) != "policy"

    def _inline_approval_request(self, tool_name: str, summary: str) -> dict[str, Any]:
        del tool_name, summary
        raise RuntimeError("OpenCode uses native permission prompts instead of Guard MCP inline approval.")


def _approval_allows(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("action") != "accept":
        return False
    content = payload.get("content")
    return isinstance(content, dict) and content.get("decision") == "approve"


def _approval_denies(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("action") != "accept":
        return False
    content = payload.get("content")
    return isinstance(content, dict) and content.get("decision") == "deny"


def _approval_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "result" in payload:
        result = payload.get("result")
        return result if isinstance(result, dict) else {"action": "cancel"}
    if "error" in payload:
        return {"action": "cancel"}
    return {"action": "cancel"}


def _decision_source(action: str, source: str) -> str:
    if source == "policy":
        return f"policy-{action}"
    return f"{source}-{action}"


def _is_notification(message: dict[str, Any]) -> bool:
    return "method" in message and "id" not in message


def _is_request(message: dict[str, Any]) -> bool:
    return "method" in message and "id" in message


def _response_key(value: object) -> str | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "CodexMcpGuardProxy",
    "CopilotMcpGuardProxy",
    "ElicitationMcpGuardProxy",
    "OpenCodeMcpGuardProxy",
    "RuntimeMcpGuardProxy",
]
