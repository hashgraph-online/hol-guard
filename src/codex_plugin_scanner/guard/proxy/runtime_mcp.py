"""Runtime MCP proxy implementations used by managed harness adapters."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, TextIO

from ..adapters.base import HarnessContext
from ..approvals import first_approval_url, queue_blocked_approvals
from ..config import GuardConfig
from ..consumer.service import artifact_hash
from ..daemon import ensure_guard_daemon
from ..mcp_tool_calls import (
    allow_tool_call,
    block_tool_call,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
    tool_call_risk_categories,
    tool_call_risk_summary,
)
from ..models import HarnessDetection
from ..policy.engine import build_decision_v2
from ..runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from ..runtime.package_intent import build_package_request_artifact, extract_package_intent_request
from ..runtime.signals import RiskSignalV2
from ..runtime.supply_chain_package_eval import evaluate_package_request_artifact
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
        server_id: str | None = None,
        server_env_keys: tuple[str, ...] = (),
        server_identity: McpServerIdentity | None = None,
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
        self.server_id = server_id
        self.server_env_keys = tuple(dict.fromkeys(key.strip() for key in server_env_keys if key.strip()))
        self.server_identity = server_identity or build_mcp_server_identity(
            config_path=self.config_path,
            command=self.command[0] if self.command else "",
            args=tuple(self.command[1:]),
            transport=self.transport,
            env_keys=self.server_env_keys,
        )
        self._inline_prompt_available = False
        self._inline_prompt_counter = 0
        self._buffered_child_responses: dict[str, list[dict[str, Any]]] = {}
        self._buffered_client_responses: dict[str, list[dict[str, Any]]] = {}
        self._tool_catalog: dict[str, dict[str, object]] = {}
        self._tool_catalog_pending: dict[str, dict[str, object]] | None = None
        self._tool_catalog_generation = 0

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
        if method in {"notifications/tools/list_changed", "tools/list_changed"}:
            self._invalidate_tools_catalog()
        if _is_notification(message):
            self._forward_notification(message, child_stdin)
            event["decision"] = "forward-notification"
            return None, event
        if not _is_request(message):
            self._forward_notification(message, child_stdin)
            event["decision"] = "forward-response"
            return None, event
        if method != "tools/call" or not isinstance(params, dict):
            list_generation = self._tool_catalog_generation if method == "tools/list" else None
            response = self._forward_message(
                message,
                child_stdin,
                child_stdout,
                client_input=client_input,
                server_output=server_output,
            )
            if method == "tools/list":
                list_cursor = params.get("cursor") if isinstance(params, dict) else None
                self._capture_tools_catalog(
                    response,
                    request_cursor=list_cursor,
                    request_generation=list_generation,
                )
            return response, event

        tool_name = str(params.get("name") or "unknown")
        arguments = params.get("arguments")
        tool_definition = self._tool_catalog.get(tool_name, {})
        artifact = build_tool_call_artifact(
            harness=self.harness,
            server_name=self.server_name,
            tool_name=tool_name,
            source_scope=self.source_scope,
            config_path=self.config_path,
            transport=self.transport,
            server_id=self.server_id,
            server_fingerprint={
                "command": self.command,
                "transport": self.transport,
            },
            server_identity=self.server_identity,
            tool_schema=tool_definition.get("input_schema"),
            tool_description=tool_definition.get("description"),
        )
        artifact_hash = build_tool_call_hash(artifact, arguments)
        decision = evaluate_tool_call(
            store=self.store,
            config=self.config,
            artifact=artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
        )
        package_artifact = self._package_request_artifact(tool_name=tool_name, arguments=arguments)
        if package_artifact is not None:
            if decision.action in {"allow", "warn"}:
                response, package_event = self._handle_package_request(
                    message=message,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                    tool_name=tool_name,
                    params=params,
                    artifact=package_artifact,
                )
                return response, package_event
            if self._allow_after_native_prompt(decision):
                response, package_event = self._handle_package_request(
                    message=message,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                    tool_name=tool_name,
                    params=params,
                    artifact=package_artifact,
                )
                return response, package_event
            if self._inline_prompt_available and approval_callback is not None:
                approval_result = approval_callback(self._inline_approval_request(tool_name, decision.summary))
                if _approval_allows(approval_result):
                    response, package_event = self._handle_package_request(
                        message=message,
                        child_stdin=child_stdin,
                        child_stdout=child_stdout,
                        client_input=client_input,
                        server_output=server_output,
                        tool_name=tool_name,
                        params=params,
                        artifact=package_artifact,
                    )
                    return response, package_event
                if _approval_denies(approval_result):
                    block_tool_call(
                        store=self.store,
                        artifact=artifact,
                        artifact_hash=artifact_hash,
                        decision_source="inline-denied",
                        now=_now(),
                        signals=decision.signals,
                        risk_categories=decision.risk_categories,
                    )
                    return _blocked_tool_response(
                        message.get("id"),
                        tool_name,
                        f"HOL Guard blocked tool call {tool_name} from {self.server_name}.",
                    ), {
                        **event,
                        "decision": "deny-inline",
                    }
                if _approval_invalid(approval_result):
                    block_tool_call(
                        store=self.store,
                        artifact=artifact,
                        artifact_hash=artifact_hash,
                        decision_source="inline-invalid",
                        now=_now(),
                        signals=decision.signals,
                        risk_categories=decision.risk_categories,
                    )
                    return _blocked_tool_response(
                        message.get("id"),
                        tool_name,
                        (
                            f"HOL Guard blocked tool call {tool_name} from {self.server_name} because inline "
                            "approval returned an invalid response."
                        ),
                    ), {
                        **event,
                        "decision": "deny-inline-invalid",
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
                risk_categories=decision.risk_categories,
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
                risk_categories=decision.risk_categories,
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
                    risk_categories=decision.risk_categories,
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
                    risk_categories=decision.risk_categories,
                )
                return _blocked_tool_response(
                    message.get("id"),
                    tool_name,
                    f"HOL Guard blocked tool call {tool_name} from {self.server_name}.",
                ), {
                    **event,
                    "decision": "deny-inline",
                }
            if _approval_invalid(approval_result):
                block_tool_call(
                    store=self.store,
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    decision_source="inline-invalid",
                    now=_now(),
                    signals=decision.signals,
                    risk_categories=decision.risk_categories,
                )
                return _blocked_tool_response(
                    message.get("id"),
                    tool_name,
                    (
                        f"HOL Guard blocked tool call {tool_name} from {self.server_name} because inline "
                        "approval returned an invalid response."
                    ),
                ), {
                    **event,
                    "decision": "deny-inline-invalid",
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

    def _package_request_artifact(self, *, tool_name: str, arguments: object) -> Any | None:
        intent = extract_package_intent_request(
            tool_name,
            arguments,
            action_envelope_command=_command_argument(arguments),
            workspace=self.context.workspace_dir,
        )
        if intent is None:
            return None
        return build_package_request_artifact(
            harness=self.harness,
            intent=intent,
            config_path=self.config_path,
            source_scope=self.source_scope,
        )

    def _handle_package_request(
        self,
        *,
        message: dict[str, Any],
        child_stdin: TextIO,
        child_stdout: TextIO,
        client_input: TextIO | None,
        server_output: TextIO | None,
        tool_name: str,
        params: dict[str, Any],
        artifact: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        artifact_digest = artifact_hash(artifact)
        stored_policy_action = self.store.resolve_policy(
            artifact.harness,
            artifact.artifact_id,
            artifact_hash=artifact_digest,
            workspace=str(self.context.workspace_dir) if self.context.workspace_dir is not None else None,
        )
        package_evaluation = evaluate_package_request_artifact(
            artifact=artifact,
            store=self.store,
            workspace_dir=self.context.workspace_dir,
        )
        policy_action = (
            stored_policy_action if isinstance(stored_policy_action, str) else package_evaluation.policy_action
        )
        if policy_action in {"allow", "warn"}:
            response = self._forward_message(
                message,
                child_stdin,
                child_stdout,
                client_input=client_input,
                server_output=server_output,
            )
            return response, {
                "method": "tools/call",
                "tool_name": tool_name,
                "decision": f"package-{policy_action}",
                "redacted_params": _redact_json(params),
            }
        approval_center_url = ensure_guard_daemon(self.context.guard_home)
        decision_v2_payload = build_decision_v2(
            policy_action,
            reason=policy_action,
            signals=_package_reason_signals(package_evaluation.reasons),
        ).to_dict()
        decision_v2_payload["user_title"] = package_evaluation.user_copy.title
        decision_v2_payload["user_body"] = package_evaluation.user_copy.summary
        decision_v2_payload["harness_message"] = package_evaluation.user_copy.harness_message
        decision_v2_payload["dashboard_primary_detail"] = package_evaluation.user_copy.summary
        should_queue_approval_center = not (policy_action == "block" and stored_policy_action == "block")
        queued: list[dict[str, Any]] = []
        if should_queue_approval_center:
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
                            "artifact_hash": artifact_digest,
                            "artifact_type": artifact.artifact_type,
                            "source_scope": artifact.source_scope,
                            "config_path": artifact.config_path,
                            "changed_fields": ["runtime_tool_call", "package_request"],
                            "policy_action": policy_action,
                            "launch_target": self._launch_target(tool_name, params.get("arguments")),
                            "risk_summary": package_evaluation.risk_summary,
                            "risk_signals": [
                                str(item.get("message") or item.get("code") or "")
                                for item in package_evaluation.reasons
                            ],
                            "decision_v2_json": decision_v2_payload,
                            "supply_chain_evaluation": package_evaluation.to_dict(),
                        }
                    ]
                },
                store=self.store,
                approval_center_url=approval_center_url,
                now=_now(),
            )
        request_id = str(queued[0]["request_id"]) if queued else "stored-block"
        review_url = first_approval_url(queued) or approval_center_url
        response_data = {
            "approvalCenterUrl": approval_center_url,
            "approvalRequests": queued,
            "reviewUrl": review_url,
            "supplyChainEvaluation": package_evaluation.to_dict(),
        }
        blocked_message = (
            f"HOL Guard stopped package install request {tool_name} from {self.server_name}. "
            f"Approve request {request_id} at {review_url}, then retry the same action."
        )
        event_decision = "queue-package-approval"
        if not should_queue_approval_center:
            blocked_message = (
                f"HOL Guard blocked package install request {tool_name} from {self.server_name}. "
                f"This same request is already blocked by stored policy. Review policy settings at {review_url} "
                f"before retrying."
            )
            event_decision = "package-block-stored"
        return _blocked_tool_response(
            message.get("id"),
            tool_name,
            blocked_message,
            response_data,
        ), {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": event_decision,
            "redacted_params": _redact_json(params),
            "approval_center_url": approval_center_url,
            "approval_requests": queued,
            "review_url": review_url,
        }

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
        risk_categories: tuple[str, ...],
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
            risk_categories=risk_categories,
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
            if str(payload.get("method", "")) in {"notifications/tools/list_changed", "tools/list_changed"}:
                self._invalidate_tools_catalog()
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
            risk_categories=tool_call_risk_categories(artifact, params.get("arguments")),
        )
        request_id = str(queued[0]["request_id"]) if queued else "unknown"
        review_url = first_approval_url(queued) or approval_center_url
        response_data = {
            "approvalCenterUrl": approval_center_url,
            "approvalRequests": queued,
            "reviewUrl": review_url,
        }
        return _blocked_tool_response(
            message_id,
            tool_name,
            (
                f"HOL Guard stopped tool call {tool_name} from {self.server_name}. "
                f"Approve request {request_id} at {review_url}, then retry the same action."
            ),
            response_data,
        ), {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "queue-approval",
            "redacted_params": _redact_json(params),
            "approval_center_url": approval_center_url,
            "approval_requests": queued,
            "review_url": review_url,
        }

    def _capture_tools_catalog(
        self,
        response: dict[str, Any],
        *,
        request_cursor: object | None = None,
        request_generation: int | None = None,
    ) -> None:
        if request_generation is not None and request_generation != self._tool_catalog_generation:
            return
        result = response.get("result")
        if not isinstance(result, dict):
            return
        tools = result.get("tools")
        if not isinstance(tools, list):
            return
        if request_cursor is None:
            self._tool_catalog_pending = None
        next_cursor = result.get("nextCursor")
        has_more_pages = next_cursor is not None
        catalog: dict[str, dict[str, object]] = {}
        for item in tools:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            entry: dict[str, object] = {}
            description = item.get("description")
            if isinstance(description, str) and description.strip():
                entry["description"] = description.strip()
            input_schema = item.get("inputSchema")
            if input_schema is not None:
                entry["input_schema"] = input_schema
            catalog[name.strip()] = entry
        if has_more_pages:
            pending_snapshot = {} if self._tool_catalog_pending is None else dict(self._tool_catalog_pending)
            pending_snapshot.update(catalog)
            self._tool_catalog_pending = pending_snapshot
            self._tool_catalog = dict(self._tool_catalog_pending)
            return
        if self._tool_catalog_pending is not None:
            merged_snapshot = dict(self._tool_catalog_pending)
            merged_snapshot.update(catalog)
            self._tool_catalog = merged_snapshot
            self._tool_catalog_pending = None
            return
        self._tool_catalog = catalog

    def _invalidate_tools_catalog(self) -> None:
        self._tool_catalog = {}
        self._tool_catalog_pending = None
        self._tool_catalog_generation += 1

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


def _approval_invalid(payload: object) -> bool:
    if not isinstance(payload, dict):
        return True
    if payload.get("action") != "accept":
        return False
    content = payload.get("content")
    if not isinstance(content, dict):
        return True
    return content.get("decision") not in {"approve", "deny"}


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


def _command_argument(arguments: object) -> str | None:
    if not isinstance(arguments, Mapping):
        return None
    for key in ("command", "cmd", "shell_command", "shellCommand"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _package_reason_signals(reasons: tuple[dict[str, object], ...]) -> tuple[RiskSignalV2, ...]:
    signals: list[RiskSignalV2] = []
    for reason in reasons:
        code = _optional_text(reason.get("code")) or "package-risk"
        message = _optional_text(reason.get("message")) or code.replace("_", " ")
        severity = _package_signal_severity(_optional_text(reason.get("severity")))
        signals.append(
            RiskSignalV2(
                signal_id=f"supply-chain.{code}",
                category="supply_chain",
                severity=severity,
                confidence="strong" if severity in {"high", "critical"} else "likely",
                detector=_optional_text(reason.get("source")) or "guard.supply-chain",
                title=message,
                plain_reason=message,
                technical_detail=message,
                evidence_ref=None,
                redaction_level="summary",
                false_positive_hint=(
                    "Review the package request or add a scoped exception only for a verified false positive."
                ),
                advisory_id=None,
            )
        )
    return tuple(signals)


def _package_signal_severity(value: str | None) -> str:
    if value in {"info", "low", "medium", "high", "critical"}:
        return value
    return "medium"


def _optional_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "CodexMcpGuardProxy",
    "CopilotMcpGuardProxy",
    "ElicitationMcpGuardProxy",
    "OpenCodeMcpGuardProxy",
    "RuntimeMcpGuardProxy",
]
