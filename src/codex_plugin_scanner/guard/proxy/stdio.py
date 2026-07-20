"""Local stdio MCP proxy helpers."""

from __future__ import annotations

import io
import json
import queue
import select
import subprocess
import threading
import webbrowser
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..action_lattice import most_restrictive_guard_action
from ..approvals import (
    approval_delivery_payload,
    approval_prompt_flow,
    build_approval_browser_url,
    first_approval_url,
    queue_blocked_approvals,
)
from ..config import GuardConfig, resolve_risk_action
from ..consumer import artifact_hash
from ..daemon.manager import load_guard_daemon_auth_token
from ..models import GuardAction, GuardArtifact, HarnessDetection
from ..receipts import build_receipt
from ..runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_configured_environment_hash,
    build_runtime_launch_identity,
    resolved_runtime_launch_executable,
    runtime_launch_identity_matches,
)
from ..runtime.approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_NO_SAVED_DECISION,
    ApprovalReuseDecision,
    ApprovalReuseValidationFailure,
    evaluate_approval_reuse,
)
from ..runtime.secret_file_requests import build_file_read_request_artifact, extract_sensitive_file_read_request
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from ._env import _build_scrubbed_env

_DEFAULT_PROXY_RESPONSE_TIMEOUT_SECONDS = 30.0
_PROXY_TERMINATION_TIMEOUT_SECONDS = 1.0
_GUARD_PROXY_TIMEOUT_ERROR_CODE = -32800
# Bump when sensitive-read classification or action-composition semantics change.
_STDIO_SENSITIVE_READ_EVALUATOR_POLICY_VERSION = "stdio-sensitive-read-evaluation-v1"
_APPROVAL_REUSE_CONFIG_REFRESH_FAILED = "approval_reuse_current_config_refresh_failed"


def _sensitive_read_current_action(
    config: object,
    *,
    artifact: GuardArtifact,
    harness: str,
) -> GuardAction:
    if not isinstance(config, GuardConfig):
        return "require-reapproval"
    configured_override = config.resolve_action_override(
        harness,
        artifact.artifact_id,
        artifact.publisher,
    )
    current_config_action = configured_override if configured_override is not None else config.default_action
    risk_action = resolve_risk_action(config, "local_secret_read", harness=harness) or "require-reapproval"
    return most_restrictive_guard_action(risk_action, current_config_action)


def build_sensitive_read_approval_hash(
    artifact: GuardArtifact,
    *,
    config: object,
    cwd: Path | None,
    current_action: GuardAction,
    server_launch_identity: Mapping[str, object] | None = None,
    configured_env_values_hash: str | None = None,
) -> str:
    """Bind a file-read approval to exact runtime, policy, and sandbox context."""

    effective_cwd = cwd or Path.cwd()
    try:
        normalized_cwd = str(effective_cwd.expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        normalized_cwd = str(effective_cwd.expanduser().absolute())
    if isinstance(config, GuardConfig):
        configured_override = config.resolve_action_override(
            artifact.harness,
            artifact.artifact_id,
            artifact.publisher,
        )
        policy_context: dict[str, object] = {
            "artifact_override": configured_override,
            "default_action": config.default_action,
            "effective_action": current_action,
            "evaluator_policy_version": _STDIO_SENSITIVE_READ_EVALUATOR_POLICY_VERSION,
            "managed_locked_settings": list(config.managed_locked_settings),
            "managed_policy_hash": config.managed_policy_hash,
            "managed_policy_status": config.managed_policy_status,
            "mode": config.mode,
            "security_level": config.security_level,
        }
        sandbox_context: dict[str, object] = {"analysis": config.sandbox_analysis}
    else:
        policy_context = {
            "config_valid": False,
            "effective_action": current_action,
            "evaluator_policy_version": _STDIO_SENSITIVE_READ_EVALUATOR_POLICY_VERSION,
        }
        sandbox_context = {"analysis": "unknown"}
    return build_approval_context_token(
        identity={
            "artifact_id": artifact.artifact_id,
            "config_path": artifact.config_path,
            "harness": artifact.harness,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
            "server_launch_identity": dict(server_launch_identity or {}),
            "configured_env_values_hash": configured_env_values_hash,
            "workspace": normalized_cwd,
        },
        content=artifact_hash(artifact),
        capabilities={
            "artifact_type": artifact.artifact_type,
            "path_class": artifact.metadata.get("path_class"),
            "tool_name": artifact.metadata.get("tool_name"),
        },
        policy=policy_context,
        sandbox=sandbox_context,
    )


def _approval_reuse_evidence(reuse: ApprovalReuseDecision) -> tuple[dict[str, object], ...]:
    if reuse.reason_code == APPROVAL_REUSE_NO_SAVED_DECISION:
        return ()
    return ({"source": "approval_reuse", **reuse.to_evidence()},)


def _sensitive_read_saved_allow_validation_reason(
    decision: dict[str, object],
    *,
    artifact_hash: str,
) -> str | None:
    if decision.get("action") != "allow":
        return None
    return approval_context_tokens_validation_reason(decision.get("artifact_hash"), artifact_hash)


def _approval_surface_policy_for_browser(configured_policy: object, approval_flow: dict[str, object]) -> str:
    if approval_flow.get("tier") != "approval-center":
        return "notify-only"
    if approval_flow.get("auto_open_browser") is False:
        return "never-auto-open"
    policy = str(configured_policy or "auto-open-once")
    if policy == "native-only":
        return "never-auto-open"
    return policy


class ProxyIoTimeoutError(TimeoutError):
    def __init__(self, *, source: str, timeout_seconds: float) -> None:
        super().__init__(f"timeout waiting for {source}")
        self.source = source
        self.timeout_seconds = timeout_seconds


class ProxyLaunchIdentityChangedError(RuntimeError):
    """Raised when launch identity changes across subprocess creation."""


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


def _sensitive_read_non_forward_message(
    policy_action: GuardAction,
    *,
    tool_name: str,
    path_class: str,
) -> str:
    if policy_action == "review":
        return f"Guard paused sensitive local file access for {tool_name} pending review: {path_class}."
    if policy_action == "require-reapproval":
        return (
            f"Guard paused sensitive local file access for {tool_name} until fresh approval is granted: {path_class}."
        )
    if policy_action == "sandbox-required":
        return (
            f"Guard requires an enforceable sandbox before sensitive local file access for {tool_name}: {path_class}."
        )
    if policy_action == "block":
        return f"Guard blocked sensitive local file access for {tool_name}: {path_class}."
    raise ValueError(f"Sensitive-read non-forward response cannot represent action {policy_action!r}.")


def _sensitive_read_review_hint(
    policy_action: GuardAction,
    *,
    approval_summary: object,
    review_url: str,
) -> str:
    if policy_action == "review":
        instruction = "review the waiting request"
    elif policy_action == "require-reapproval":
        instruction = "grant or deny fresh approval"
    else:
        raise ValueError(f"Sensitive-read approval hint cannot represent action {policy_action!r}.")
    return f"{approval_summary} Open {review_url} to {instruction}."


def _timeout_response(
    message_id: Any,
    *,
    source: str,
    timeout_seconds: float,
    message: str,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": _GUARD_PROXY_TIMEOUT_ERROR_CODE,
            "message": message,
            "data": {
                "guard_timeout": True,
                "source": source,
                "timeout_seconds": timeout_seconds,
            },
        },
    }


def _is_timeout_response(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    error = payload.get("error")
    if not isinstance(error, dict):
        return False
    data = error.get("data")
    return (
        error.get("code") == _GUARD_PROXY_TIMEOUT_ERROR_CODE
        and isinstance(data, dict)
        and data.get("guard_timeout") is True
    )


def _stream_fileno(stream: Any) -> int | None:
    try:
        fileno = stream.fileno()
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        return None
    return fileno if isinstance(fileno, int) and fileno >= 0 else None


def _readline_with_timeout(
    stream: Any,
    timeout_seconds: float,
    *,
    source: str,
    allow_background_wait: bool = True,
) -> str:
    fileno = None if allow_background_wait else _stream_fileno(stream)
    if fileno is not None:
        try:
            ready, _, _ = select.select([fileno], [], [], timeout_seconds)
        except (OSError, ValueError) as exc:
            raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds) from exc
        if not ready:
            raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
        return stream.readline()
    if not allow_background_wait:
        if isinstance(stream, io.StringIO):
            return stream.readline()
        raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
    result_queue: queue.Queue[tuple[bool, str | BaseException]] = queue.Queue(maxsize=1)

    def _reader() -> None:
        try:
            result_queue.put((True, stream.readline()))
        except BaseException as exc:  # pragma: no cover - surfaced through queue
            result_queue.put((False, exc))

    threading.Thread(target=_reader, daemon=True).start()
    try:
        ok, result = result_queue.get(timeout=timeout_seconds)
    except queue.Empty as exc:
        raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds) from exc
    if ok:
        return result if isinstance(result, str) else ""
    if isinstance(result, BaseException):
        raise result
    raise RuntimeError("guard_proxy_io_failed")


def _quarantine_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    with suppress(Exception):
        process.terminate()
    try:
        process.wait(timeout=_PROXY_TERMINATION_TIMEOUT_SECONDS)
        return
    except Exception:
        pass
    with suppress(Exception):
        process.kill()
    with suppress(Exception):
        process.wait(timeout=_PROXY_TERMINATION_TIMEOUT_SECONDS)


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
        current_config_provider: Callable[[], GuardConfig] | None = None,
    ) -> None:
        self.command = command
        self.blocked_tools = blocked_tools or set()
        self.cwd = cwd
        self.guard_store = guard_store
        self.guard_config = guard_config
        self.approval_center_url = approval_center_url
        self.harness = harness
        self.env = env or {}
        self._current_config_provider = current_config_provider
        self._active_launch_identity: dict[str, object] | None = None
        self._active_env_values_hash: str | None = None

    def _response_timeout_seconds(self) -> float:
        configured = getattr(self.guard_config, "approval_wait_timeout_seconds", None)
        if isinstance(configured, (int, float)) and configured > 0:
            return min(float(configured), _DEFAULT_PROXY_RESPONSE_TIMEOUT_SECONDS)
        return _DEFAULT_PROXY_RESPONSE_TIMEOUT_SECONDS

    def _maybe_open_approval_center(self, *, review_url: str, open_key: str) -> None:
        if self.guard_store is None or self.approval_center_url is None:
            return
        managed_install = self.guard_store.get_managed_install(self.harness)
        approval_flow = approval_prompt_flow(
            self.harness,
            managed_install=managed_install,
        )
        approval_surface_policy = _approval_surface_policy_for_browser(
            getattr(self.guard_config, "approval_surface_policy", "auto-open-once"),
            approval_flow,
        )
        if approval_surface_policy in {"notify-only", "never-auto-open"}:
            return
        browser_url = build_approval_browser_url(
            review_url,
            auth_token=load_guard_daemon_auth_token(self.guard_store.guard_home),
        )
        GuardSurfaceRuntime(self.guard_store).ensure_surface(
            surface="approval-center",
            approval_center_url=self.approval_center_url,
            browser_url=browser_url,
            approval_surface_policy=approval_surface_policy,
            open_key=open_key,
            opener=webbrowser.open,
        )

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
                    if _is_timeout_response(response):
                        break
            assert process.stdin is not None
            process.stdin.close()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            self._active_launch_identity = None
            self._active_env_values_hash = None
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
                if responses and _is_timeout_response(responses[-1]):
                    break
            assert process.stdin is not None
            process.stdin.close()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            self._active_launch_identity = None
            self._active_env_values_hash = None
        return responses, events, process.returncode

    def _start_process(self) -> subprocess.Popen[str]:
        launch_env = _build_scrubbed_env(self.env)
        self._active_launch_identity = self._build_launch_identity(launch_env)
        self._active_env_values_hash = build_configured_environment_hash(
            launch_env,
            configured_keys=tuple(self.env),
        )
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True,
                cwd=self.cwd,
                env=launch_env,
                executable=resolved_runtime_launch_executable(self._active_launch_identity),
            )
            if not self._active_launch_identity_matches(launch_env):
                raise ProxyLaunchIdentityChangedError(
                    "Guard stdio proxy launch identity changed while starting the MCP server."
                )
            return process
        except BaseException:
            if process is not None:
                _quarantine_process(process)
            self._active_launch_identity = None
            self._active_env_values_hash = None
            raise

    def _build_launch_identity(self, launch_env: Mapping[str, str]) -> dict[str, object]:
        command = self.command[0] if self.command else ""
        return build_runtime_launch_identity(
            command,
            args=self.command[1:],
            structured_command=True,
            search_path=launch_env.get("PATH"),
            cwd=self.cwd or Path.cwd(),
            launch_env=launch_env,
        )

    def _active_launch_identity_matches(self, launch_env: Mapping[str, str]) -> bool:
        identity = self._active_launch_identity
        command = self.command[0] if self.command else ""
        return identity is not None and runtime_launch_identity_matches(
            identity,
            command,
            args=self.command[1:],
            structured_command=True,
            search_path=launch_env.get("PATH"),
            cwd=self.cwd or Path.cwd(),
            launch_env=launch_env,
        )

    def _session_launch_identity(self) -> dict[str, object]:
        if self._active_launch_identity is not None:
            return dict(self._active_launch_identity)
        return self._build_launch_identity(_build_scrubbed_env(self.env))

    def _session_env_values_hash(self) -> str:
        if self._active_env_values_hash is not None:
            return self._active_env_values_hash
        return build_configured_environment_hash(
            _build_scrubbed_env(self.env),
            configured_keys=tuple(self.env),
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
                current_action = _sensitive_read_current_action(
                    self.guard_config,
                    artifact=runtime_artifact,
                    harness=self.harness,
                )
                runtime_artifact_hash = build_sensitive_read_approval_hash(
                    runtime_artifact,
                    config=self.guard_config,
                    cwd=self.cwd,
                    current_action=current_action,
                    server_launch_identity=self._session_launch_identity(),
                    configured_env_values_hash=self._session_env_values_hash(),
                )
                policy_lookup = (
                    self.guard_store.resolve_policy_decision_lookup(
                        self.harness,
                        runtime_artifact.artifact_id,
                        artifact_hash=runtime_artifact_hash,
                        workspace=str(self.cwd) if self.cwd is not None else None,
                        publisher=runtime_artifact.publisher,
                        consume_one_shot=False,
                    )
                    if self.guard_store is not None
                    else None
                )
                saved_decision = policy_lookup["decision"] if policy_lookup is not None else None
                ignored_integrity = policy_lookup["ignored_local_integrity"] if policy_lookup is not None else None
                diagnosed_reason: ApprovalReuseValidationFailure | None = None
                if saved_decision is None and ignored_integrity is None and self.guard_store is not None:
                    raw_diagnosed_reason = self.guard_store.approval_reuse_validation_reason(
                        self.harness,
                        runtime_artifact.artifact_id,
                        runtime_artifact_hash,
                        str(self.cwd) if self.cwd is not None else None,
                        runtime_artifact.publisher,
                    )
                    if raw_diagnosed_reason is not None:
                        diagnosed_reason = cast(ApprovalReuseValidationFailure, raw_diagnosed_reason)
                saved_action = (
                    saved_decision.get("action")
                    if saved_decision is not None
                    else (
                        "require-reapproval"
                        if ignored_integrity is not None
                        else ("allow" if diagnosed_reason is not None else None)
                    )
                )
                validation_reason: ApprovalReuseValidationFailure | None = (
                    "approval_reuse_integrity_failure"
                    if ignored_integrity is not None
                    else (
                        cast(
                            ApprovalReuseValidationFailure,
                            _sensitive_read_saved_allow_validation_reason(
                                saved_decision,
                                artifact_hash=runtime_artifact_hash,
                            ),
                        )
                        if saved_decision is not None
                        else diagnosed_reason
                    )
                )
                reuse = evaluate_approval_reuse(
                    current_action,
                    saved_action,
                    saved_decision_present=(
                        saved_decision is not None or ignored_integrity is not None or diagnosed_reason is not None
                    ),
                    validation_reason=validation_reason,
                )
                claimed_allow_hash: str | None = None
                config_refresh_failed = False
                if reuse.should_claim and saved_decision is not None and self.guard_store is not None:
                    if not self.guard_store.claim_approval_reuse_decision(saved_decision):
                        reuse = evaluate_approval_reuse(
                            current_action,
                            saved_action,
                            saved_decision_present=True,
                            validation_reason=APPROVAL_REUSE_CLAIM_FAILED,
                        )
                    else:
                        claimed_allow_hash = runtime_artifact_hash
                if claimed_allow_hash is not None:
                    # The atomic claim is authority only for the exact context it
                    # consumed. Rebuild every policy and launch-bound input after
                    # the claim so a concurrent policy/identity change cannot use
                    # the stale pre-claim allow to reach the child process.
                    assert self.guard_store is not None
                    provider = self._current_config_provider
                    try:
                        fresh_config = provider() if provider is not None else None
                    except Exception:
                        fresh_config = None
                    if not isinstance(fresh_config, GuardConfig):
                        config_refresh_failed = True
                        reuse = evaluate_approval_reuse(
                            "require-reapproval",
                            "allow",
                            saved_decision_present=True,
                        )
                    else:
                        self.guard_config = fresh_config
                        fresh_artifact = build_file_read_request_artifact(
                            harness=self.harness,
                            request=sensitive_request,
                            config_path=str(self._policy_path()),
                            source_scope="project" if self.cwd is not None else "global",
                        )
                        fresh_current_action = _sensitive_read_current_action(
                            fresh_config,
                            artifact=fresh_artifact,
                            harness=self.harness,
                        )
                        fresh_artifact_hash = build_sensitive_read_approval_hash(
                            fresh_artifact,
                            config=fresh_config,
                            cwd=self.cwd,
                            current_action=fresh_current_action,
                            server_launch_identity=self._session_launch_identity(),
                            configured_env_values_hash=self._session_env_values_hash(),
                        )
                        fresh_lookup = self.guard_store.resolve_policy_decision_lookup(
                            self.harness,
                            fresh_artifact.artifact_id,
                            artifact_hash=fresh_artifact_hash,
                            workspace=str(self.cwd) if self.cwd is not None else None,
                            publisher=fresh_artifact.publisher,
                            consume_one_shot=False,
                        )
                        fresh_saved_decision = fresh_lookup["decision"]
                        fresh_ignored_integrity = fresh_lookup["ignored_local_integrity"]
                        if fresh_ignored_integrity is not None:
                            postclaim_saved_action = (
                                fresh_saved_decision.get("action")
                                if fresh_saved_decision is not None
                                else "require-reapproval"
                            )
                            postclaim_validation_reason: ApprovalReuseValidationFailure | None = (
                                "approval_reuse_integrity_failure"
                            )
                        elif fresh_saved_decision is not None and fresh_saved_decision.get("action") != "allow":
                            postclaim_saved_action = fresh_saved_decision.get("action")
                            postclaim_validation_reason = None
                        else:
                            postclaim_saved_action = "allow"
                            postclaim_validation_reason = cast(
                                ApprovalReuseValidationFailure,
                                approval_context_tokens_validation_reason(
                                    claimed_allow_hash,
                                    fresh_artifact_hash,
                                ),
                            )
                        reuse = evaluate_approval_reuse(
                            fresh_current_action,
                            postclaim_saved_action,
                            saved_decision_present=True,
                            validation_reason=postclaim_validation_reason,
                        )
                        runtime_artifact = fresh_artifact
                        runtime_artifact_hash = fresh_artifact_hash
                        current_action = fresh_current_action
                policy_action = (
                    "require-reapproval"
                    if reuse.action == "review" and reuse.reason_code != APPROVAL_REUSE_NO_SAVED_DECISION
                    else reuse.action
                )
                reuse_evidence = _approval_reuse_evidence(reuse)
                if config_refresh_failed:
                    reuse_evidence = (
                        *reuse_evidence,
                        {
                            "source": "approval_reuse",
                            "status": "rejected",
                            "reason_code": _APPROVAL_REUSE_CONFIG_REFRESH_FAILED,
                            "effective_action": "require-reapproval",
                        },
                    )
                terminal_saved_block = reuse.action == "block" and reuse.saved_action == "block"
                terminal_policy_action = policy_action in {"block", "sandbox-required"}
                event["artifact_id"] = runtime_artifact.artifact_id
                event["artifact_type"] = runtime_artifact.artifact_type
                event["path_summary"] = sensitive_request.path_match.normalized_path
                event["risk_summary"] = runtime_artifact.metadata.get("runtime_request_summary")
                event["approval_reuse_status"] = reuse.status
                event["approval_reuse_reason_code"] = (
                    _APPROVAL_REUSE_CONFIG_REFRESH_FAILED if config_refresh_failed else reuse.reason_code
                )
                if terminal_saved_block:
                    event["terminal_saved_block"] = True
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
                            approval_source=(
                                "approval_center"
                                if policy_action == "require-reapproval" and self.approval_center_url is not None
                                else "policy"
                            ),
                            scanner_evidence=reuse_evidence,
                        )
                    )
                forwarded = policy_action in {"allow", "warn"}
                event["decision"] = policy_action
                event["policy_action"] = policy_action
                event["transport_outcome"] = "forwarded" if forwarded else "not-forwarded"
                if policy_action in {"block", "review", "sandbox-required", "require-reapproval"}:
                    non_forward_message = _sensitive_read_non_forward_message(
                        policy_action,
                        tool_name=tool_name,
                        path_class=sensitive_request.path_match.path_class,
                    )
                    response_data: dict[str, Any] = {
                        "guardPolicyAction": policy_action,
                        "transportOutcome": "not-forwarded",
                    }
                    if (
                        self.guard_store is not None
                        and self.approval_center_url is not None
                        and not terminal_policy_action
                    ):
                        event["approval_requests"] = queue_blocked_approvals(
                            redaction_level=getattr(self.guard_config, "receipt_redaction_level", "full"),
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
                                        "scanner_evidence": list(reuse_evidence),
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
                        review_url = (
                            first_approval_url(
                                event["approval_requests"],
                                approval_center_url=self.approval_center_url,
                            )
                            or self.approval_center_url
                        )
                        request_id = next(
                            (
                                str(item["request_id"])
                                for item in event["approval_requests"]
                                if isinstance(item, dict) and isinstance(item.get("request_id"), str)
                            ),
                            "waiting-request",
                        )
                        self._maybe_open_approval_center(review_url=review_url, open_key=request_id)
                        event["review_hint"] = _sensitive_read_review_hint(
                            policy_action,
                            approval_summary=approval_flow["summary"],
                            review_url=review_url,
                        )
                        non_forward_message = f"{non_forward_message} {event['review_hint']}"
                        response_data.update(
                            {
                                "approvalCenterUrl": self.approval_center_url,
                                "approvalRequests": event["approval_requests"],
                                "approvalDelivery": event["approval_delivery"],
                                "reviewHint": event["review_hint"],
                                "reviewUrl": review_url,
                            }
                        )
                    response = _blocked_tool_response(
                        message.get("id"),
                        tool_name,
                        non_forward_message,
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
        if _is_timeout_response(response):
            event["transport_outcome"] = "timeout"
            if "policy_action" not in event:
                event["decision"] = "timeout"
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
            timeout_seconds = self._response_timeout_seconds()
            try:
                line = _readline_with_timeout(process.stdout, timeout_seconds, source="child_response")
            except ProxyIoTimeoutError:
                _quarantine_process(process)
                return _timeout_response(
                    message_id,
                    source="child_response",
                    timeout_seconds=timeout_seconds,
                    message="Guard stdio proxy timed out waiting for the MCP server.",
                )
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
