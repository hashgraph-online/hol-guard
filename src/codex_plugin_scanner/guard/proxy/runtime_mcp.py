"""Runtime MCP proxy implementations used by managed harness adapters."""

from __future__ import annotations

import io
import json
import os
import queue
import shlex
import sys
import threading
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import IO, Any, Literal, TextIO, cast
from uuid import uuid4

from ..action_lattice import (
    normalize_guard_action,
)
from ..adapters.base import HarnessContext
from ..approval_gate import ApprovalGateError
from ..approval_scope_support import package_request_runtime_workspace_scope
from ..approvals import approval_prompt_flow, build_approval_browser_url, first_approval_url, queue_blocked_approvals
from ..blocked_request_mode import asks_for_approval, safe_alternative_reason
from ..browser_opener import open_browser_url
from ..config import GuardConfig
from ..daemon import ensure_guard_daemon
from ..daemon.manager import load_guard_daemon_auth_token
from ..local_supply_chain import (
    _cleanup_external_archive_downloads,
    _package_evaluation_requires_external_archive_binding,
    _resolve_stored_package_policy_override,
    _verified_external_archive_replacements,
    compose_current_package_policy_action,
    evaluate_package_request_artifact,
    package_external_archive_override,
    package_request_policy_hash,
)
from ..mcp_tool_calls import (
    ToolCallDecision,
    allow_tool_call,
    block_tool_call,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
    tool_call_risk_categories,
    tool_call_risk_summary,
)
from ..models import GuardAction, GuardArtifact, HarnessDetection
from ..native_approval_proof import (
    ApprovalReuseClaimDisposition,
    claimed_approval_authorizes_postclaim_review,
    fresh_claim_allows_reapproval,
)
from ..native_execution import (
    mcp_stdio_session_close_native,
    mcp_stdio_session_open_native,
    mcp_stdio_session_recv_native,
    mcp_stdio_session_send_native,
)
from ..native_mcp_proxy_decision import (
    NativeMcpProxyDecisionError,
    cursor_fact,
    native_mcp_proxy_decide,
    package_facts,
    tool_facts,
)
from ..package_execution_context import build_package_execution_context
from ..policy.engine import build_decision_v2
from ..runtime.approval_context import (
    build_configured_environment_hash,
    build_runtime_launch_identity,
    resolved_runtime_launch_executable,
    runtime_launch_identity_matches,
)
from ..runtime.browser_mcp_intent import normalize_browser_mcp_intent
from ..runtime.composio_contract import composio_requires_action_review
from ..runtime.harness_attribution import origin_harness_env
from ..runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity
from ..runtime.package_intent import build_package_request_artifact, extract_package_intent_request
from ..runtime.signals import RiskSeverityLabel, RiskSignalV2
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from ..tool_decision_evidence import tool_decision_scanner_evidence as _tool_decision_scanner_evidence
from ._env import _build_scrubbed_env
from .stdio import (
    ProxyIoTimeoutError,
    _blocked_tool_response,
    _is_timeout_response,
    _quarantine_process,
    _readline_with_timeout,
    _timeout_response,
)


def _guard_action(value: object) -> GuardAction:
    return normalize_guard_action(value)


_SHELL_COMMAND_ARGUMENT_KEYS = frozenset({"cmd", "command", "shellCommand", "shell_command"})


class _ExternalArchiveBindingError(ValueError):
    pass


def _replace_external_archive_shell_command(
    command: str,
    *,
    replacements: Mapping[str, str],
    matched_sources: set[str],
) -> str:
    if not any(source_url in command for source_url in replacements):
        return command
    if sys.platform == "win32":
        raise _ExternalArchiveBindingError("opaque Windows shell command cannot safely bind archive path")
    if "`" in command or "$(" in command or "\n" in command or "\r" in command:
        raise _ExternalArchiveBindingError("compound shell expression cannot safely bind archive path")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError as error:
        raise _ExternalArchiveBindingError("shell command could not be parsed for archive binding") from error
    if any(token and all(character in "();<>|&" for character in token) for token in tokens):
        raise _ExternalArchiveBindingError("compound shell command cannot safely bind archive path")
    bound_tokens: list[str] = []
    for token in tokens:
        bound_token = token
        for source_url, local_path in replacements.items():
            if source_url not in bound_token:
                continue
            bound_token = bound_token.replace(source_url, local_path)
            matched_sources.add(source_url)
        bound_tokens.append(bound_token)
    return shlex.join(bound_tokens)


def _replace_external_archive_values(
    value: object,
    *,
    replacements: Mapping[str, str],
    matched_sources: set[str],
    shell_command: bool = False,
) -> object:
    if isinstance(value, str):
        if shell_command:
            return _replace_external_archive_shell_command(
                value,
                replacements=replacements,
                matched_sources=matched_sources,
            )
        replaced = value
        for source_url, local_path in replacements.items():
            if source_url not in replaced:
                continue
            replaced = replaced.replace(source_url, local_path)
            matched_sources.add(source_url)
        return replaced
    if isinstance(value, list):
        return [
            _replace_external_archive_values(
                item,
                replacements=replacements,
                matched_sources=matched_sources,
                shell_command=False,
            )
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _replace_external_archive_values(
                item,
                replacements=replacements,
                matched_sources=matched_sources,
                shell_command=key in _SHELL_COMMAND_ARGUMENT_KEYS and isinstance(item, str),
            )
            for key, item in value.items()
        }
    return value


def _bound_external_archive_mcp_request(
    message: dict[str, Any],
    params: dict[str, Any],
    *,
    evaluation: object,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    replacements = _verified_external_archive_replacements(evaluation)
    if replacements is None:
        return None
    requires_binding = _package_evaluation_requires_external_archive_binding(evaluation)
    if not replacements:
        return None if requires_binding else (message, params)
    matched_sources: set[str] = set()
    try:
        bound_params = cast(
            dict[str, Any],
            _replace_external_archive_values(
                deepcopy(params),
                replacements=replacements,
                matched_sources=matched_sources,
            ),
        )
    except _ExternalArchiveBindingError:
        return None
    if matched_sources != set(replacements):
        return None
    bound_message = deepcopy(message)
    bound_message["params"] = bound_params
    return bound_message, bound_params


def _approval_surface_policy_for_browser(configured_policy: object, approval_flow: Mapping[str, object]) -> str:
    if approval_flow.get("tier") != "approval-center":
        return "notify-only"
    if approval_flow.get("auto_open_browser") is False:
        return "never-auto-open"
    policy = str(configured_policy or "auto-open-once")
    if policy == "native-only":
        return "never-auto-open"
    return policy


def _tool_decision_after_runtime_allow(decision: ToolCallDecision, *, source: str) -> ToolCallDecision:
    return replace(
        decision,
        action="allow",
        source=source,
        pending_approval_reuse_decision=None,
        approval_reuse_claim_disposition=None,
    )


def _safe_mcp_arguments(value: object) -> object:
    """Project MCP arguments into a display/persistence-safe representation.

    Native authority only: the resident `mcp_arguments_projection` op owns the
    secret-shaped-key masking, URL query redaction, and scalar fragment tables.
    `None` means no `arguments` key — preserved so absent and null digest alike.
    Native failure is terminal; the silent-Python-redaction fallback was an
    accountability leak (secrets could persist unredacted).
    """
    from ..native_context import context_mcp_arguments_projection

    safe_arguments, _launch, _digest = context_mcp_arguments_projection("", value)
    return safe_arguments


def _safe_mcp_params(params: Mapping[str, object]) -> dict[str, object]:
    return cast(dict[str, object], _safe_mcp_arguments(params))


def _mcp_arguments_digest(arguments: object) -> str:
    """sha256 over the canonical JSON encoding of the RAW arguments."""
    from ..native_context import context_mcp_arguments_projection

    _safe, _launch, digest = context_mcp_arguments_projection("", arguments)
    return digest


def _browser_intent_payload(
    artifact: Any,
    arguments: object,
    *,
    default_launch_target: str,
) -> tuple[str, dict[str, object] | None]:
    """Project the launch target label and safe browser intent payload for a tool call."""
    browser_intent = normalize_browser_mcp_intent(artifact, arguments)
    if browser_intent is None:
        return default_launch_target, None
    # Build a safer browser-specific launch target label
    target = browser_intent.target_domain or browser_intent.target_origin or "unknown"
    launch_target = f"{browser_intent.mcp_server_name} {browser_intent.operation} {target}"
    browser_intent_dict = cast(
        dict[str, object],
        _safe_mcp_arguments(
            {
                "version": browser_intent.version,
                "intent": browser_intent.intent,
                "operation": browser_intent.operation,
                "target_url": browser_intent.target_url,
                "target_origin": browser_intent.target_origin,
                "target_domain": browser_intent.target_domain,
                "target_path_prefix": browser_intent.target_path_prefix,
                "method": browser_intent.method,
                "profile_mode": browser_intent.profile_mode,
                "mcp_server_name": browser_intent.mcp_server_name,
                "mcp_server_identity_hash": browser_intent.mcp_server_identity_hash,
                "mcp_tool_name": browser_intent.mcp_tool_name,
                "mcp_tool_identity_hash": browser_intent.mcp_tool_identity_hash,
                "mcp_schema_hash": browser_intent.mcp_schema_hash,
                "sensitive_surface_flags": list(browser_intent.sensitive_surface_flags),
                "volatile_fields_dropped": list(browser_intent.volatile_fields_dropped),
            }
        ),
    )
    return launch_target, browser_intent_dict


_ToolCatalogState = Literal["unobserved", "pending", "complete", "invalidated", "error"]
_TOOL_CATALOG_EXECUTION_BOUNDARY_CHANGED = "tool_catalog_changed_at_execution_boundary"
_TOOLS_CALL_PREWRITE_QUIET_SECONDS = 0.005


class _ToolCatalogBoundaryChangedError(RuntimeError):
    """The catalog authority changed before a guarded tool call was written."""


@dataclass(frozen=True, slots=True)
class _ChildOutputFrame:
    line: str | None = None
    error: BaseException | None = None


class _NativeMcpChildIo:
    """Child-side transport over the native MCP stdio session ops (RTM-022/023).

    Quacks like the pipe pair ``_forward_message``/``_drain_child_messages``
    use: ``write``/``flush`` frame a client→child message via ``send``;
    ``next_frame`` surfaces the next inbound child event via ``recv``. The
    resident owns the subprocess, newline framing, correlation, and teardown;
    this adapter only marshals frames. Returned ``line`` values are re-parsed
    by the relay so the existing catalog-poison/quarantine gate is preserved.
    """

    def __init__(self, session_id: str, guard_home: Path) -> None:
        self._session_id = session_id
        self._guard_home = guard_home
        self._pending: deque[str] = deque()
        self.exit_code: int | None = None

    # stdin side ------------------------------------------------------------
    def write(self, data: str) -> int:
        """Accept a ``json.dumps(message) + "\\n"`` write like a text pipe."""
        text = data.rstrip("\n")
        try:
            message = json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise RuntimeError("native MCP session received a non-JSON frame") from exc
        result = mcp_stdio_session_send_native(self._session_id, message, guard_home=self._guard_home)
        if result is None or result.get("status") != "sent":
            raise RuntimeError("native MCP session send failed")
        return len(data)

    def flush(self) -> None:  # resident op is already synchronous/flushed
        return None

    def writelines(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.write(line)

    def close(self) -> None:
        mcp_stdio_session_close_native(self._session_id, guard_home=self._guard_home)

    # stdout side -----------------------------------------------------------
    def next_frame(self, timeout_seconds: float, required: bool) -> _ChildOutputFrame | None:
        # Test/injection seam: locally-queued frames are delivered before the
        # resident so callers can synthesize inbound child events (e.g.
        # `tools/list_changed`) without a native inject op.
        if self._pending:
            return _ChildOutputFrame(line=self._pending.popleft())
        result = mcp_stdio_session_recv_native(
            self._session_id,
            guard_home=self._guard_home,
            timeout_seconds=timeout_seconds,
        )
        if result is None:
            return _ChildOutputFrame(error=RuntimeError("native MCP session recv transport failure"))
        status = str(result.get("status", ""))
        if status == "event":
            payload = result.get("payload")
            return _ChildOutputFrame(line=json.dumps(payload) + "\n")
        if status in {"exited", "eof"}:
            code = result.get("exit_code")
            if isinstance(code, int) and not isinstance(code, bool):
                self.exit_code = code
            return _ChildOutputFrame()
        if status == "timeout":
            if required:
                return _ChildOutputFrame(
                    error=ProxyIoTimeoutError(source="child_response", timeout_seconds=timeout_seconds)
                )
            return None
        # "error" status — surface as a frame error so the relay fails closed.
        code = result.get("payload")
        return _ChildOutputFrame(error=RuntimeError(f"native MCP session error: {code}"))

    def readline(self) -> str:  # pragma: no cover - compatibility sink
        return ""


class _NativeChildProcess:
    """Popen-shaped adapter over a resident-owned MCP stdio session.

    ``serve``/``run_session`` only touch ``stdin``/``stdout``/teardown; the
    resident owns the real subprocess, so ``stdin``/``stdout`` share one
    ``_NativeMcpChildIo`` transport and lifecycle calls delegate to ``close``.
    ``returncode`` is available after the resident reports child exit; clean
    close returns ``0`` and quarantine/cancel returns ``-9``.
    """

    def __init__(self, session_id: str, guard_home: Path) -> None:
        self._session_id = session_id
        self._guard_home = guard_home
        io = _NativeMcpChildIo(session_id, guard_home)
        self.stdin: _NativeMcpChildIo = io
        self.stdout: _NativeMcpChildIo = io
        self.stderr = None
        self._closed = False
        self._cancelled = False
        self._returncode: int | None = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        mcp_stdio_session_close_native(self._session_id, guard_home=self._guard_home)

    def terminate(self) -> None:
        self.close()

    def kill(self) -> None:
        self._cancelled = True
        self.close()

    def poll(self) -> int | None:
        if self._returncode is not None:
            return self._returncode
        if self.stdin.exit_code is not None:
            self._returncode = self.stdin.exit_code
            return self._returncode
        if self._cancelled:
            return -9
        if self._closed:
            return 0
        result = mcp_stdio_session_recv_native(
            self._session_id,
            guard_home=self._guard_home,
            timeout_seconds=1.0,
            poll_only=True,
        )
        if result is not None and result.get("status") == "exited":
            exit_code = result.get("exit_code")
            self._returncode = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else -1
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        self.close()
        returncode = self.returncode
        if returncode is None:
            raise RuntimeError("Native MCP session closed without an exit status.")
        return returncode

    @property
    def returncode(self) -> int | None:
        return self.poll()


def _tool_catalog_fingerprint(
    catalog: Mapping[str, Mapping[str, object]],
    *,
    state: _ToolCatalogState = "complete",
) -> str:
    """Hash catalog lifecycle state plus the complete canonical tool surface.

    Canonicalization and hashing are native authority; this delegates. The
    native validator returns `None` when the canonical document can't be
    serialized — Python's `json.dumps(..., allow_nan=False)` raised
    `ValueError` on the same condition, so this raises too.
    """
    from ..native_context import context_mcp_tool_catalog_fingerprint

    fingerprint, _ = context_mcp_tool_catalog_fingerprint(catalog, state=state)
    if fingerprint is None:
        raise ValueError("mcp_tool_catalog_fingerprint_unserializable")
    return fingerprint


def _resolved_executable_identity(
    command: str,
    *,
    launch_cwd: Path | None,
    launch_env: Mapping[str, str] | None = None,
    launch_args: Sequence[str] = (),
) -> dict[str, object]:
    """Bind the executable Popen will resolve after applying its ``cwd``."""

    effective_launch_env = launch_env if launch_env is not None else _build_scrubbed_env()
    launch_identity = build_runtime_launch_identity(
        command,
        args=launch_args,
        structured_command=True,
        search_path=effective_launch_env.get("PATH"),
        cwd=launch_cwd or Path.cwd(),
        launch_env=effective_launch_env,
    )
    executable = launch_identity["executable"]
    identity = dict(executable) if isinstance(executable, Mapping) else {}
    identity["command"] = command
    identity["launch_cwd"] = launch_identity["launch_cwd"]
    identity["entrypoint"] = launch_identity["entrypoint"]
    return identity


def _configured_server_environment(
    launch_env: Mapping[str, str],
    configured_keys: Sequence[str],
) -> dict[str, str]:
    """Select only configured server values from the actual child environment."""

    return {key: launch_env[key] for key in configured_keys if key in launch_env}


def _configured_server_launch_environment(configured_keys: Sequence[str]) -> dict[str, str]:
    """Build a scrubbed child environment plus only explicitly configured values."""

    configured_values = {key: os.environ[key] for key in configured_keys if key in os.environ}
    return _build_scrubbed_env(configured_values)


def _ensure_native_launch_resident_verifier(store: GuardStore) -> None:
    """Provision the resident verifier key before any native launch RPC.

    See `native_policy_snapshot_publisher.ensure_native_launch_resident_verifier`
    — the same prerequisite is shared with the stdio proxy, which opens native
    resident sessions through a different entrypoint.
    """

    from ..native_policy_snapshot_publisher import ensure_native_launch_resident_verifier

    ensure_native_launch_resident_verifier(store)


@dataclass(frozen=True, slots=True)
class _PackagePolicyResolution:
    base_evaluation: Any
    evaluation: Any
    current_action: GuardAction
    workspace: Path
    execution_context: Any
    artifact_digest: str
    policy_workspace: str | None
    saved_policy_blocks: bool
    pending_approval_reuse_decision: Mapping[str, object] | None
    approval_reuse_claim_disposition: ApprovalReuseClaimDisposition | None = None


@dataclass(frozen=True, slots=True)
class _ToolCallAuthority:
    artifact: GuardArtifact
    artifact_hash: str
    decision: ToolCallDecision
    catalog_generation: int
    catalog_state: _ToolCatalogState
    catalog_fingerprint: str


@dataclass(frozen=True, slots=True)
class _PostclaimForward:
    """Forwarding state the resident cleared after saved approvals were claimed."""

    authoritative_action: GuardAction
    artifact: Any
    resolution: _PackagePolicyResolution
    scanner_evidence: tuple[Any, ...]
    catalog_generation: int
    catalog_state: _ToolCatalogState
    catalog_fingerprint: str


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
        current_config_provider: Callable[[], GuardConfig] | None = None,
    ) -> None:
        self.harness = harness
        self.server_name = server_name
        self.command = command
        self.context = context
        self.store = store
        from ..native_context import bind_context_digest_home

        bind_context_digest_home(context.guard_home)
        self.config = config
        self.source_scope = source_scope
        self.config_path = config_path
        self.transport = transport
        self.server_id = server_id
        self._current_config_provider = current_config_provider
        self.server_env_keys = tuple(dict.fromkeys(key.strip() for key in server_env_keys if key.strip()))
        _ensure_native_launch_resident_verifier(self.store)
        initial_launch_env = _configured_server_launch_environment(self.server_env_keys)
        self.server_identity = server_identity or build_mcp_server_identity(
            config_path=self.config_path,
            command=self.command[0] if self.command else "",
            args=tuple(self.command[1:]),
            transport=self.transport,
            env=_configured_server_environment(initial_launch_env, self.server_env_keys),
            env_keys=self.server_env_keys,
        )
        self._inline_prompt_available = False
        self._inline_prompt_counter = 0
        self._buffered_child_responses: dict[str, list[dict[str, Any]]] = {}
        self._buffered_client_responses: dict[str, list[dict[str, Any]]] = {}
        self._child_output_queue: queue.Queue[_ChildOutputFrame] | None = None
        self._active_child_stdout: IO[str] | _NativeMcpChildIo | None = None
        self._tools_call_boundary_lock = threading.RLock()
        self._tool_catalog_state: _ToolCatalogState = "unobserved"
        self._tool_catalog: dict[str, dict[str, object]] = {}
        self._tool_catalog_pending: dict[str, dict[str, object]] | None = None
        self._tool_catalog_expected_cursor: str | None = None
        self._tool_catalog_inflight = False
        self._tool_catalog_inflight_cursor: str | None = None
        self._tool_catalog_generation = 0
        self._active_process: _NativeChildProcess | None = None
        self._active_runtime_launch_identity: dict[str, object] | None = None
        self._active_executable_identity: dict[str, object] | None = None
        self._active_server_env_values_hash: str | None = None
        self._active_server_identity: McpServerIdentity | None = None

    def _child_response_timeout_seconds(self) -> float:
        configured = getattr(self.config, "approval_wait_timeout_seconds", None)
        if isinstance(configured, (int, float)) and configured > 0:
            return min(float(configured), 30.0)
        return 30.0

    def _nested_request_timeout_seconds(self) -> float:
        return self._child_response_timeout_seconds()

    def _inline_approval_timeout_seconds(self) -> float:
        configured = getattr(self.config, "approval_wait_timeout_seconds", None)
        if isinstance(configured, (int, float)) and configured > 0:
            return float(configured)
        return 120.0

    def _maybe_open_approval_center(self, *, approval_center_url: str, review_url: str, open_key: str) -> None:
        managed_install = self.store.get_managed_install(self.harness)
        approval_flow = approval_prompt_flow(self.harness, managed_install=managed_install)
        approval_surface_policy = _approval_surface_policy_for_browser(
            self.config.approval_surface_policy,
            approval_flow,
        )
        if approval_surface_policy in {"notify-only", "never-auto-open"}:
            return
        browser_url = build_approval_browser_url(
            review_url,
            auth_token=load_guard_daemon_auth_token(self.context.guard_home),
        )
        GuardSurfaceRuntime(self.store).ensure_surface(
            surface="approval-center",
            approval_center_url=approval_center_url,
            browser_url=browser_url,
            approval_surface_policy=approval_surface_policy,
            open_key=open_key,
            opener=open_browser_url,
        )

    def run_session(
        self,
        messages: list[dict[str, Any]],
        *,
        inline_approval_callback: Any | None = None,
    ) -> dict[str, Any]:
        process = self._start_process()
        responses: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        self._active_process = process
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            child_stdin = process.stdin
            child_stdout = process.stdout
            for message in messages:
                response, event = self._handle_message(
                    message=message,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=None,
                    server_output=None,
                    approval_callback=inline_approval_callback,
                )
                if response is not None:
                    responses.append(response)
                    if _is_timeout_response(response):
                        events.append(event)
                        break
                events.append(event)
            process.stdin.close()
            process.wait(timeout=5)
        finally:
            self._active_process = None
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            self._active_executable_identity = None
            self._active_runtime_launch_identity = None
            self._active_server_env_values_hash = None
            self._active_server_identity = None
            self._deactivate_child_process_io()
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
        self._active_process = process
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            child_stdin = process.stdin
            child_stdout = process.stdout
            while True:
                line = input_stream.readline()
                if not line:
                    break
                message = json.loads(line)
                response, _ = self._handle_message(
                    message=message,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=input_stream,
                    server_output=output_stream,
                    approval_callback=lambda request: self._request_inline_approval(
                        request,
                        input_stream=input_stream,
                        output_stream=output_stream,
                        child_stdin=child_stdin,
                        child_stdout=child_stdout,
                    ),
                )
                if response is not None:
                    output_stream.write(json.dumps(response) + "\n")
                    output_stream.flush()
                    if _is_timeout_response(response):
                        break
            process.stdin.close()
            process.wait(timeout=5)
            return int(process.returncode or 0)
        finally:
            self._active_process = None
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            self._active_executable_identity = None
            self._active_runtime_launch_identity = None
            self._active_server_env_values_hash = None
            self._active_server_identity = None
            self._deactivate_child_process_io()

    def _reset_child_process_state(self) -> None:
        self._buffered_child_responses.clear()
        self._buffered_client_responses.clear()
        self._child_output_queue = None
        self._active_child_stdout = None
        self._reset_tools_catalog_unobserved()

    def _deactivate_child_process_io(self) -> None:
        self._buffered_child_responses.clear()
        self._buffered_client_responses.clear()
        self._child_output_queue = None
        self._active_child_stdout = None

    def _prepare_launch(self) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """Compute launch identity/env shared by the Popen and native paths.

        Populates ``self._active_*`` identity fields; callers clear them on
        failure. Native resident must be reachable — these calls raise.
        """
        self._reset_child_process_state()
        launch_env = _configured_server_launch_environment(self.server_env_keys)
        child_env = dict(launch_env)
        child_env.update(origin_harness_env(self.harness))
        configured_env = _configured_server_environment(launch_env, self.server_env_keys)
        self._active_runtime_launch_identity = build_runtime_launch_identity(
            self.command[0] if self.command else "",
            args=self.command[1:],
            structured_command=True,
            search_path=launch_env.get("PATH"),
            cwd=self.context.workspace_dir or Path.cwd(),
            launch_env=launch_env,
        )
        self._active_executable_identity = _resolved_executable_identity(
            self.command[0] if self.command else "",
            launch_cwd=self.context.workspace_dir,
            launch_env=launch_env,
            launch_args=self.command[1:],
        )
        self._active_server_env_values_hash = build_configured_environment_hash(
            launch_env,
            configured_keys=self.server_env_keys,
        )
        self._active_server_identity = build_mcp_server_identity(
            config_path=self.config_path,
            command=self.command[0] if self.command else "",
            args=tuple(self.command[1:]),
            transport=self.transport,
            env=configured_env,
            env_keys=self.server_env_keys,
        )
        return launch_env, child_env, configured_env

    def _clear_launch_identity(self) -> None:
        self._active_executable_identity = None
        self._active_runtime_launch_identity = None
        self._active_server_env_values_hash = None
        self._active_server_identity = None

    def _start_process(self) -> _NativeChildProcess:
        """Launch only through the resident that owns the migrated data plane."""
        native_session_id: str | None = None
        try:
            launch_env, child_env, _configured_env = self._prepare_launch()
            identity = self._active_runtime_launch_identity
            if identity is None:
                raise RuntimeError("Guard runtime MCP server executable could not be verified.")
            executable = resolved_runtime_launch_executable(identity)
            if not isinstance(executable, str) or not executable:
                raise RuntimeError("Guard runtime MCP server executable could not be verified.")
            argv = [executable, *self.command[1:]]
            native_session_id = f"mcp-{self.harness}-{self.server_name}-{os.getpid()}-{uuid4().hex[:8]}"
            opened = mcp_stdio_session_open_native(
                argv,
                session_id=native_session_id,
                home_dir=Path(child_env["HOME"]) if child_env.get("HOME") else None,
                cwd=self.context.workspace_dir or Path.cwd(),
                extra_env=child_env,
                guard_home=self.context.guard_home,
            )
            if opened is None:
                # An ambiguous transport result can follow a successful spawn.
                # Keep the id for cleanup; never create a second Python child.
                raise RuntimeError("Native MCP session authority is unavailable.")
            if opened.get("status") != "opened":
                raise RuntimeError(f"native MCP session open failed: {opened.get('payload')}")
            if not self._verify_post_spawn_launch_identity(launch_env=launch_env):
                raise RuntimeError(
                    "Guard runtime MCP server launch identity changed while the child process was starting."
                )
            # This queue injects already-decoded notifications into the relay;
            # it is not a Python child-process transport or output reader.
            self._child_output_queue = queue.Queue()
            return _NativeChildProcess(native_session_id, self.context.guard_home)
        except BaseException:
            try:
                if native_session_id is not None:
                    mcp_stdio_session_close_native(native_session_id, guard_home=self.context.guard_home)
            except Exception:
                # Preserve the original launch failure even if cleanup's
                # transport is unavailable. Never retry through Python.
                pass
            finally:
                self._clear_launch_identity()
            raise

    def _verify_post_spawn_launch_identity(self, *, launch_env: Mapping[str, str]) -> bool:
        """Re-hash launch inputs after native spawn and reject a spawn-time swap."""

        expected = self._active_runtime_launch_identity
        if expected is None:
            return False
        return runtime_launch_identity_matches(
            expected,
            self.command[0] if self.command else "",
            args=self.command[1:],
            structured_command=True,
            search_path=launch_env.get("PATH"),
            cwd=self.context.workspace_dir or Path.cwd(),
            launch_env=launch_env,
        )

    def _session_executable_identity(self) -> dict[str, object]:
        identity = self._active_executable_identity
        if identity is None:
            identity = _resolved_executable_identity(
                self.command[0] if self.command else "",
                launch_cwd=self.context.workspace_dir,
                launch_args=self.command[1:],
            )
        return dict(identity)

    def _session_server_env_values_hash(self) -> str:
        active_hash = self._active_server_env_values_hash
        if active_hash is not None:
            return active_hash
        launch_env = _configured_server_launch_environment(self.server_env_keys)
        return build_configured_environment_hash(
            launch_env,
            configured_keys=self.server_env_keys,
        )

    def _session_server_identity(self) -> McpServerIdentity:
        identity = self._active_server_identity
        if identity is not None:
            return identity
        launch_env = _configured_server_launch_environment(self.server_env_keys)
        return build_mcp_server_identity(
            config_path=self.config_path,
            command=self.command[0] if self.command else "",
            args=tuple(self.command[1:]),
            transport=self.transport,
            env=_configured_server_environment(launch_env, self.server_env_keys),
            env_keys=self.server_env_keys,
        )

    def _claim_boundary_config(self) -> GuardConfig:
        provider = self._current_config_provider
        if provider is None:
            raise RuntimeError("runtime_mcp_current_config_provider_unavailable")
        config = provider()
        if not isinstance(config, GuardConfig):
            raise RuntimeError("runtime_mcp_current_config_provider_invalid")
        return config

    def _catalog_boundary_failure_response(
        self,
        *,
        message_id: object,
        tool_name: str,
        params: dict[str, Any],
        scanner_evidence: tuple[dict[str, object], ...],
        phase: str,
        package_request: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fresh_authority = self._resolve_tool_call_authority(
            tool_name=tool_name,
            arguments=params.get("arguments"),
        )
        fresh_decision = fresh_authority.decision
        outcome = self._native_decide(
            {"check": "boundary_failure", "phase": phase, "fresh": tool_facts(fresh_decision)}
        )
        evidence = (
            *scanner_evidence,
            *_tool_decision_scanner_evidence(fresh_decision),
            *outcome["evidence_append"],
        )
        if outcome["kind"] == "stored_block":
            return self._stored_tool_block_response(
                message_id=message_id,
                artifact=fresh_authority.artifact,
                artifact_hash=fresh_authority.artifact_hash,
                tool_name=tool_name,
                params=params,
                signals=fresh_decision.signals,
                risk_categories=fresh_decision.risk_categories,
                scanner_evidence=evidence,
                package_request=package_request,
            )
        if outcome["kind"] == "terminal":
            return self._terminal_tool_response(
                message_id=message_id,
                artifact=fresh_authority.artifact,
                artifact_hash=fresh_authority.artifact_hash,
                tool_name=tool_name,
                params=params,
                policy_action=outcome["policy_action"],
                signals=fresh_decision.signals,
                risk_categories=fresh_decision.risk_categories,
                scanner_evidence=evidence,
            )
        return self._queue_approval_center_response(
            message_id=message_id,
            artifact=fresh_authority.artifact,
            artifact_hash=fresh_authority.artifact_hash,
            tool_name=tool_name,
            signals=fresh_decision.signals,
            params=params,
            scanner_evidence=evidence,
            policy_action=outcome["policy_action"],
        )

    def _native_decide(
        self,
        query: Mapping[str, object],
        *,
        supply: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Ask the native resident for a proxy decision; any failure raises."""

        return native_mcp_proxy_decide(query, guard_home=Path(self.store.guard_home), supply=supply)

    def _native_evidence_item(self, kind: str) -> dict[str, object]:
        """The resident's evidence item for a claim or config refresh failure."""

        return dict(self._native_decide({"check": "evidence_item", "kind": kind})["item"])

    def _apply_saved_allow_gate(self, decision: ToolCallDecision) -> ToolCallDecision:
        """Present the resident's saved-allow gate verdict on a decision."""

        gate = self._native_decide(
            {
                "check": "saved_allow_gate",
                "catalog_state": self._tool_catalog_state,
                "decision": tool_facts(decision),
            }
        )
        if not gate["disable"]:
            return decision
        return replace(
            decision,
            action=gate["action"],
            source=gate["source"],
            summary=gate["summary"],
            approval_reuse_status=gate["approval_reuse_status"],
            approval_reuse_reason_code=gate["approval_reuse_reason_code"],
            pending_approval_reuse_decision=None,
            approval_reuse_claim_disposition=None,
        )

    def _resolve_tool_call_authority(
        self,
        *,
        tool_name: str,
        arguments: object,
        config: GuardConfig | None = None,
    ) -> _ToolCallAuthority:
        """Rebuild the complete current tool-call identity and policy result."""

        authority_config = config or self.config
        tool_definition = self._tool_catalog.get(tool_name, {})
        tool_description_value = tool_definition.get("description")
        tool_schema = tool_definition.get("inputSchema", tool_definition.get("input_schema"))
        # The native canonical catalog page retains `name` inside each entry.
        # Strip it before building the public artifact so the name-matched
        # `mcp_tool_authority_hash` is not written into hash-affecting
        # `metadata`; the full definition is bound via
        # `runtime_private_metadata` below without changing the exact
        # saved-block artifact hash.
        public_tool_definition = {key: value for key, value in tool_definition.items() if key != "name"}
        catalog_generation = self._tool_catalog_generation
        catalog_state = self._tool_catalog_state
        catalog_fingerprint = _tool_catalog_fingerprint(
            self._tool_catalog,
            state=catalog_state,
        )
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
                "configured_env_values_hash": self._session_server_env_values_hash(),
                "transport": self.transport,
                "resolved_executable": self._session_executable_identity(),
                "tool_catalog_state": catalog_state,
                "tool_catalog_fingerprint": catalog_fingerprint,
            },
            server_identity=self._session_server_identity(),
            tool_schema=tool_schema,
            tool_description=tool_description_value if isinstance(tool_description_value, str) else None,
            tool_definition=public_tool_definition,
            provider_catalog_hash=(
                self.store.read_mcp_provider_authority_hash() if composio_requires_action_review(tool_name) else None
            ),
        )
        if tool_name in self._tool_catalog:
            from ..store_mcp_catalog import tool_definition_authority_hash

            # Catalog entries omit their name because it is the map key. Bind
            # the full definition for local grants without changing the
            # artifact hash used by existing exact saved blocks.
            artifact = replace(
                artifact,
                runtime_private_metadata={
                    **artifact.runtime_private_metadata,
                    "mcp_tool_authority_hash": tool_definition_authority_hash({"name": tool_name, **tool_definition}),
                },
            )
        artifact_hash = build_tool_call_hash(
            artifact,
            arguments,
            workspace=self.context.workspace_dir or Path.cwd(),
            config=authority_config,
        )
        decision = self._apply_saved_allow_gate(
            evaluate_tool_call(
                store=self.store,
                config=authority_config,
                artifact=artifact,
                artifact_hash=artifact_hash,
                arguments=arguments,
                claim_saved_approval=False,
            )
        )
        return _ToolCallAuthority(
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision=decision,
            catalog_generation=catalog_generation,
            catalog_state=catalog_state,
            catalog_fingerprint=catalog_fingerprint,
        )

    def _handle_message(
        self,
        *,
        message: dict[str, Any],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        approval_callback: Any | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        if str(message.get("method", "")) == "tools/call":
            with self._tools_call_boundary_lock:
                return self._handle_message_serialized(
                    message=message,
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                    approval_callback=approval_callback,
                )
        return self._handle_message_serialized(
            message=message,
            child_stdin=child_stdin,
            child_stdout=child_stdout,
            client_input=client_input,
            server_output=server_output,
            approval_callback=approval_callback,
        )

    def _deny_inline_tool_call(
        self,
        *,
        decision_source: str,
        event_decision: str,
        reason: str,
        message: dict[str, Any],
        tool_name: str,
        event: dict[str, Any],
        artifact: GuardArtifact,
        artifact_hash: str,
        decision: ToolCallDecision,
        scanner_evidence: tuple[dict[str, object], ...],
        arguments: object,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        block_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source=decision_source,
            now=_now(),
            signals=decision.signals,
            risk_categories=decision.risk_categories,
            arguments=_safe_mcp_arguments(arguments),
            additional_scanner_evidence=scanner_evidence,
            policy_action="block",
        )
        return _blocked_tool_response(
            message.get("id"),
            tool_name,
            reason,
            {"approvalRequests": [], "guardPolicyAction": "block"},
        ), {
            **event,
            "decision": event_decision,
            "policy_action": "block",
            "approval_requests": [],
        }

    def _inline_approval_deny_result(
        self,
        approval_result: object,
        deny_tool_call: Callable[..., tuple[dict[str, Any], dict[str, Any]]],
        tool_name: str,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        if _approval_denies(approval_result):
            return deny_tool_call(
                decision_source="inline-denied",
                event_decision="deny-inline",
                reason=f"HOL Guard blocked tool call {tool_name} from {self.server_name}.",
            )
        if _approval_invalid(approval_result):
            return deny_tool_call(
                decision_source="inline-invalid",
                event_decision="deny-inline-invalid",
                reason=(
                    f"HOL Guard blocked tool call {tool_name} from {self.server_name} because inline "
                    "approval returned an invalid response."
                ),
            )
        return None

    def _handle_message_serialized(
        self,
        *,
        message: dict[str, Any],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        approval_callback: Any | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        method = str(message.get("method", "unknown"))
        params = message.get("params", {})
        self._record_client_capabilities(method, params)
        event: dict[str, Any] = {
            "method": method,
            "tool_name": params.get("name") if isinstance(params, dict) else None,
            "decision": "forward",
            "redacted_params": _safe_mcp_params(params) if isinstance(params, Mapping) else {},
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
            list_cursor: object | None = None
            list_generation: int | None = None
            if method == "tools/list":
                list_cursor = params.get("cursor") if isinstance(params, dict) else object()
                list_generation = self._begin_tools_catalog_request(list_cursor)
            try:
                response = self._forward_message(
                    message,
                    child_stdin,
                    child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                )
            except BaseException:
                if list_generation is not None:
                    self._fail_tools_catalog_request(list_generation)
                raise
            if method == "tools/list":
                assert list_generation is not None
                self._capture_tools_catalog(
                    response,
                    request_cursor=list_cursor,
                    request_generation=list_generation,
                )
            if _is_timeout_response(response):
                event["decision"] = "timeout"
            return response, event

        try:
            self._drain_child_messages(
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
            )
        except Exception:
            self._poison_tools_catalog()
            tool_name = str(params.get("name") or "unknown")
            return _blocked_tool_response(
                message.get("id"),
                tool_name,
                "HOL Guard could not synchronize the MCP server notification stream before this tool call.",
                {"approvalRequests": [], "guardPolicyAction": "require-reapproval"},
            ), {
                **event,
                "decision": "catalog-sync-failed",
                "policy_action": "require-reapproval",
                "approval_requests": [],
            }

        try:
            return self._handle_tool_call(
                message=message,
                params=params,
                event=event,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                approval_callback=approval_callback,
            )
        except (NativeMcpProxyDecisionError, KeyError, TypeError):
            # No authoritative native answer, or one whose shape the proxy cannot
            # read: nothing executes.
            return _blocked_tool_response(
                message.get("id"),
                str(params.get("name") or "unknown"),
                "HOL Guard could not obtain a native decision for this tool call.",
                {"approvalRequests": [], "guardPolicyAction": "block"},
            ), {
                **event,
                "decision": "native-decision-unavailable",
                "policy_action": "block",
                "approval_requests": [],
            }

    @staticmethod
    def _apply_decision_override(decision: ToolCallDecision, override: Mapping[str, Any] | None) -> ToolCallDecision:
        """Present the resident's observe-mode downgrade of a tool decision."""

        if override is None:
            return decision
        return replace(
            decision,
            action=override["action"],
            source=override["source"],
            pending_approval_reuse_decision=None,
            approval_reuse_claim_disposition=None,
        )

    def _route_tool_call(
        self,
        *,
        decision: ToolCallDecision,
        tool_name: str,
        package_artifact: Any | None,
        approval_callback: Any | None,
        held: dict[str, Any],
    ) -> dict[str, Any]:
        """Ask the resident how one tool call routes, supplying facts on demand."""

        def effective(need: Mapping[str, Any]) -> ToolCallDecision:
            return self._apply_decision_override(decision, need.get("decision_override"))

        def package_policy(_need: Mapping[str, Any]) -> dict[str, object]:
            resolution = self._resolve_package_policy(artifact=package_artifact)
            held["package_resolution"] = resolution
            return {"package_saved_policy_blocks": bool(resolution.saved_policy_blocks)}

        def native_prompt(need: Mapping[str, Any]) -> dict[str, object]:
            return {"native_prompt_allows": bool(self._allow_after_native_prompt(effective(need)))}

        def inline_approval(need: Mapping[str, Any]) -> dict[str, object]:
            if approval_callback is None:
                return {"inline_approval": "fallthrough"}
            result = approval_callback(self._inline_approval_request(tool_name, effective(need).summary))
            held["approval_result"] = result
            return {"inline_approval": _inline_approval_kind(result)}

        return self._native_decide(
            {
                "check": "route_tool_call",
                "mode": self.config.mode,
                "package_present": package_artifact is not None,
                "asks_for_approval": bool(asks_for_approval(self.config)),
                "inline_available": bool(self._inline_prompt_available and approval_callback is not None),
                "tool_name": tool_name,
                "decision": tool_facts(decision),
            },
            supply={
                "package_policy": package_policy,
                "native_prompt": native_prompt,
                "inline_approval": inline_approval,
            },
        )

    def _handle_tool_call(
        self,
        *,
        message: dict[str, Any],
        params: dict[str, Any],
        event: dict[str, Any],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        approval_callback: Any | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        tool_name = str(params.get("name") or "unknown")
        arguments = params.get("arguments")
        authority = self._resolve_tool_call_authority(tool_name=tool_name, arguments=arguments)
        artifact = authority.artifact
        tool_artifact_hash = authority.artifact_hash
        package_artifact = self._package_request_artifact(tool_name=tool_name, arguments=arguments)
        held: dict[str, Any] = {}
        routed = self._route_tool_call(
            decision=authority.decision,
            tool_name=tool_name,
            package_artifact=package_artifact,
            approval_callback=approval_callback,
            held=held,
        )
        decision = self._apply_decision_override(authority.decision, routed["decision_override"])
        decision_scanner_evidence = _tool_decision_scanner_evidence(decision)
        route = routed["route"]
        kind = route["kind"]
        tool_policy_action = routed["tool_policy_action"]
        boundary: dict[str, Any] = {
            "expected_catalog_generation": authority.catalog_generation,
            "expected_catalog_state": authority.catalog_state,
            "expected_catalog_fingerprint": authority.catalog_fingerprint,
        }

        def queue() -> tuple[dict[str, Any], dict[str, Any]]:
            return self._queue_approval_center_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=tool_artifact_hash,
                tool_name=tool_name,
                signals=decision.signals,
                params=params,
                scanner_evidence=decision_scanner_evidence,
                policy_action=tool_policy_action,
            )

        if kind == "stored_block":
            return self._stored_tool_block_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=tool_artifact_hash,
                tool_name=tool_name,
                params=params,
                signals=decision.signals,
                risk_categories=decision.risk_categories,
                scanner_evidence=decision_scanner_evidence,
                package_request=package_artifact is not None,
            )
        if kind == "terminal":
            return self._terminal_tool_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=tool_artifact_hash,
                tool_name=tool_name,
                params=params,
                policy_action=route["policy_action"],
                signals=decision.signals,
                risk_categories=decision.risk_categories,
                scanner_evidence=decision_scanner_evidence,
            )
        if kind == "queue":
            return queue()
        if kind == "inline_denied":
            denied = self._inline_approval_deny_result(
                held.get("approval_result"),
                deny_tool_call=partial(
                    self._deny_inline_tool_call,
                    message=message,
                    tool_name=tool_name,
                    event=event,
                    artifact=artifact,
                    artifact_hash=tool_artifact_hash,
                    decision=decision,
                    scanner_evidence=decision_scanner_evidence,
                    arguments=arguments,
                ),
                tool_name=tool_name,
            )
            if denied is None:
                raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_inline_unbound")
            return denied
        if kind == "package":
            extra: dict[str, Any] = {}
            if route["inline_record"]:
                try:
                    allow_tool_call(
                        store=self.store,
                        artifact=artifact,
                        artifact_hash=tool_artifact_hash,
                        decision_source="inline-approved",
                        now=_now(),
                        signals=decision.signals,
                        risk_categories=decision.risk_categories,
                        remember=bool(route["remember"]),
                        arguments=_safe_mcp_arguments(arguments),
                        additional_scanner_evidence=decision_scanner_evidence,
                        emit_runtime_evidence=False,
                    )
                except ApprovalGateError:
                    return queue()
                extra = {
                    "remember_allow": bool(route["remember"]),
                    "remember_decision_source": "inline-approved",
                    "remember_signals": decision.signals,
                    "remember_risk_categories": decision.risk_categories,
                }
            tool_source = route["tool_source"]
            return self._handle_package_request(
                message=message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                tool_name=tool_name,
                params=params,
                artifact=package_artifact,
                tool_artifact=artifact,
                tool_artifact_hash=tool_artifact_hash,
                tool_decision=(
                    decision
                    if tool_source is None
                    else _tool_decision_after_runtime_allow(decision, source=tool_source)
                ),
                tool_scanner_evidence=decision_scanner_evidence,
                package_resolution=held["package_resolution"],
                expected_catalog_generation=authority.catalog_generation,
                expected_catalog_state=authority.catalog_state,
                expected_catalog_fingerprint=authority.catalog_fingerprint,
                **extra,
            )
        if kind == "allow_and_forward":
            return self._allow_and_forward(
                message=message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                artifact=artifact,
                artifact_hash=tool_artifact_hash,
                decision_source=route["decision_source"],
                signals=decision.signals,
                risk_categories=decision.risk_categories,
                params=params,
                remember=bool(route["remember"]),
                scanner_evidence=decision_scanner_evidence,
                policy_action=route["policy_action"],
                approval_decision=decision if route["pass_approval_decision"] else None,
                **boundary,
            )
        if kind == "observe_forward":
            return self._observe_tool_forward(
                message=message,
                params=params,
                tool_name=tool_name,
                arguments=arguments,
                authority=authority,
                decision_scanner_evidence=decision_scanner_evidence,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
            )
        raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_route_unknown")

    def _observe_tool_forward(
        self,
        *,
        message: dict[str, Any],
        params: dict[str, Any],
        tool_name: str,
        arguments: object,
        authority: _ToolCallAuthority,
        decision_scanner_evidence: tuple[dict[str, object], ...],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        try:
            catalog_current = self._drain_and_validate_catalog_authority(
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                generation=authority.catalog_generation,
                state=authority.catalog_state,
                fingerprint=authority.catalog_fingerprint,
            )
        except Exception:
            self._poison_tools_catalog()
            catalog_current = False
        if not catalog_current:
            return self._catalog_boundary_failure_response(
                message_id=message.get("id"),
                tool_name=tool_name,
                params=params,
                scanner_evidence=decision_scanner_evidence,
                phase="before_observe_revalidation",
                package_request=False,
            )
        fresh_authority = self._resolve_tool_call_authority(tool_name=tool_name, arguments=arguments)
        fresh_decision = fresh_authority.decision
        observed = self._native_decide({"check": "observe_tool_forward", "fresh": tool_facts(fresh_decision)})
        executed_action = observed["executed_action"]
        response, observe_event = self._allow_and_forward(
            message=message,
            child_stdin=child_stdin,
            child_stdout=child_stdout,
            client_input=client_input,
            server_output=server_output,
            artifact=fresh_authority.artifact,
            artifact_hash=fresh_authority.artifact_hash,
            decision_source="policy-observe",
            signals=fresh_decision.signals,
            risk_categories=fresh_decision.risk_categories,
            params=params,
            scanner_evidence=(*_tool_decision_scanner_evidence(fresh_decision), *observed["evidence_append"]),
            policy_action=executed_action,
            expected_catalog_generation=fresh_authority.catalog_generation,
            expected_catalog_state=fresh_authority.catalog_state,
            expected_catalog_fingerprint=fresh_authority.catalog_fingerprint,
        )
        final_observe_event = {**observe_event, "decision": executed_action, "observe_mode": True}
        if observed["observe_override"]:
            final_observe_event["observed_policy_action"] = observed["observed_policy_action"]
        return response, final_observe_event

    def _package_request_artifact(self, *, tool_name: str, arguments: object) -> Any | None:
        intent = extract_package_intent_request(
            tool_name,
            arguments,
            action_envelope_command=_command_argument(arguments),
            workspace=self.context.workspace_dir,
            guard_home=self.context.guard_home,
        )
        if intent is None:
            return None
        return build_package_request_artifact(
            harness=self.harness,
            intent=intent,
            config_path=self.config_path,
            source_scope=self.source_scope,
        )

    def _resolve_package_policy(
        self,
        *,
        artifact: Any,
        external_archive_network_authorized: bool = False,
    ) -> _PackagePolicyResolution:
        package_evaluation = evaluate_package_request_artifact(
            artifact=artifact,
            store=self.store,
            workspace_dir=self.context.workspace_dir,
            external_archive_network_authorized=external_archive_network_authorized,
            retain_external_archive_blob=external_archive_network_authorized,
        )
        try:
            package_current_action = compose_current_package_policy_action(
                artifact=artifact,
                evaluation=package_evaluation,
                config=self.config,
            )
            package_workspace = self.context.workspace_dir or Path.cwd()
            package_context = build_package_execution_context(
                workspace_dir=package_workspace,
                artifact=artifact,
            )
            artifact_digest = package_request_policy_hash(
                artifact=artifact,
                store=self.store,
                workspace_dir=package_workspace,
                evaluation=package_evaluation,
                execution_context=package_context,
                config=self.config,
            )
            policy_workspace = package_request_runtime_workspace_scope(
                artifact_id=artifact.artifact_id,
                artifact_hash=artifact_digest,
                artifact_type=artifact.artifact_type,
                execution_context=package_context,
            )
            stored_package_resolution = _resolve_stored_package_policy_override(
                package_evaluation,
                store=self.store,
                artifact=artifact,
                artifact_hash=artifact_digest,
                workspace_dir=package_workspace,
                now=_now(),
                execution_context=package_context,
                current_action=package_current_action,
                claim_saved_approval=False,
            )
            resolved_package_evaluation = stored_package_resolution.evaluation
            return _PackagePolicyResolution(
                base_evaluation=package_evaluation,
                evaluation=resolved_package_evaluation,
                current_action=package_current_action,
                workspace=package_workspace,
                execution_context=package_context,
                artifact_digest=artifact_digest,
                policy_workspace=policy_workspace,
                saved_policy_blocks=_has_saved_package_block(resolved_package_evaluation.reasons),
                pending_approval_reuse_decision=stored_package_resolution.approval_reuse_decision,
                approval_reuse_claim_disposition=stored_package_resolution.claim_disposition,
            )
        except BaseException:
            _cleanup_external_archive_downloads(package_evaluation)
            raise

    def _handle_package_request(
        self,
        *,
        message: dict[str, Any],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        tool_name: str,
        params: dict[str, Any],
        artifact: Any,
        tool_artifact: Any,
        tool_artifact_hash: str,
        tool_decision: ToolCallDecision,
        tool_scanner_evidence: tuple[dict[str, object], ...],
        package_resolution: _PackagePolicyResolution,
        expected_catalog_generation: int,
        expected_catalog_state: _ToolCatalogState,
        expected_catalog_fingerprint: str,
        remember_allow: bool = False,
        remember_decision_source: str | None = None,
        remember_signals: tuple[str, ...] = (),
        remember_risk_categories: tuple[str, ...] = (),
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        package_evaluation = package_resolution.evaluation
        scanner_evidence = self._package_scanner_evidence(
            resolution=package_resolution,
            tool_evidence=tool_scanner_evidence,
        )
        try:
            catalog_current = self._drain_and_validate_catalog_authority(
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                generation=expected_catalog_generation,
                state=expected_catalog_state,
                fingerprint=expected_catalog_fingerprint,
            )
        except Exception:
            self._poison_tools_catalog()
            catalog_current = False
        if not catalog_current:
            return self._catalog_boundary_failure_response(
                message_id=message.get("id"),
                tool_name=tool_name,
                params=params,
                scanner_evidence=scanner_evidence,
                phase="before_package_revalidation",
                package_request=True,
            )
        precheck = self._native_decide(
            {
                "check": "package_precheck",
                "mode": self.config.mode,
                "saved_policy_blocks": bool(package_resolution.saved_policy_blocks),
                "policy_action": package_evaluation.policy_action,
            }
        )
        if precheck["kind"] == "stored_package_block":
            return self._stored_package_block_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=package_evaluation,
                scanner_evidence=scanner_evidence,
            )
        if precheck["kind"] == "terminal":
            return self._terminal_package_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=package_evaluation,
                policy_action=precheck["policy_action"],
                scanner_evidence=scanner_evidence,
            )
        if precheck["kind"] == "queue":
            return self._queue_package_approval_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=package_evaluation,
                policy_action=precheck["policy_action"],
                scanner_evidence=scanner_evidence,
            )
        if precheck["kind"] != "proceed":
            raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_precheck_unknown")

        fresh_tool_authority = self._resolve_tool_call_authority(
            tool_name=tool_name,
            arguments=params.get("arguments"),
        )
        tool_artifact = fresh_tool_authority.artifact
        tool_artifact_hash = fresh_tool_authority.artifact_hash
        fresh_tool_decision = fresh_tool_authority.decision
        expected_catalog_generation = fresh_tool_authority.catalog_generation
        expected_catalog_state = fresh_tool_authority.catalog_state
        expected_catalog_fingerprint = fresh_tool_authority.catalog_fingerprint
        fresh_package_resolution = self._resolve_package_policy(artifact=artifact)
        fresh_tool_evidence = _tool_decision_scanner_evidence(fresh_tool_decision)
        fresh_scanner_evidence = self._package_scanner_evidence(
            resolution=fresh_package_resolution,
            tool_evidence=fresh_tool_evidence,
        )
        composed = self._native_decide(
            {
                "check": "package_compose",
                "mode": self.config.mode,
                "tool": tool_facts(fresh_tool_decision),
                "package": package_facts(fresh_package_resolution),
            }
        )
        compose_kind = composed["kind"]
        if compose_kind == "stored_tool_block":
            return self._stored_tool_block_response(
                message_id=message.get("id"),
                artifact=tool_artifact,
                artifact_hash=tool_artifact_hash,
                tool_name=tool_name,
                params=params,
                signals=fresh_tool_decision.signals,
                risk_categories=fresh_tool_decision.risk_categories,
                scanner_evidence=fresh_tool_evidence,
                package_request=True,
            )
        if compose_kind == "stored_package_block":
            return self._stored_package_block_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=fresh_package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=fresh_package_resolution.evaluation,
                scanner_evidence=fresh_scanner_evidence,
            )
        if compose_kind == "terminal_tool":
            return self._terminal_tool_response(
                message_id=message.get("id"),
                artifact=tool_artifact,
                artifact_hash=tool_artifact_hash,
                tool_name=tool_name,
                params=params,
                policy_action=composed["policy_action"],
                signals=fresh_tool_decision.signals,
                risk_categories=fresh_tool_decision.risk_categories,
                scanner_evidence=fresh_tool_evidence,
            )
        if compose_kind == "terminal_package":
            return self._terminal_package_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=fresh_package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=fresh_package_resolution.evaluation,
                policy_action=composed["policy_action"],
                scanner_evidence=fresh_scanner_evidence,
            )
        if compose_kind == "queue_tool":
            return self._queue_approval_center_response(
                message_id=message.get("id"),
                artifact=tool_artifact,
                artifact_hash=tool_artifact_hash,
                tool_name=tool_name,
                signals=fresh_tool_decision.signals,
                params=params,
                scanner_evidence=fresh_tool_evidence,
                policy_action=composed["policy_action"],
            )
        if compose_kind == "queue_package":
            return self._queue_package_approval_response(
                message_id=message.get("id"),
                artifact=artifact,
                artifact_hash=fresh_package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=fresh_package_resolution.evaluation,
                policy_action=composed["policy_action"],
                scanner_evidence=fresh_scanner_evidence,
            )
        if compose_kind == "observe_forward":
            if composed["queue_observed_tool"] is not None:
                self._queue_observed_approval_requests(
                    artifact=tool_artifact,
                    artifact_hash=tool_artifact_hash,
                    tool_name=tool_name,
                    params=params,
                    policy_action=composed["queue_observed_tool"],
                    risk_summary=fresh_tool_decision.summary,
                    risk_signals=list(fresh_tool_decision.signals),
                    extra_fields={"scanner_evidence": list(fresh_tool_evidence)},
                )
            if composed["queue_observed_package"] is not None:
                self._queue_observed_package_request(
                    artifact=artifact,
                    artifact_hash=fresh_package_resolution.artifact_digest,
                    tool_name=tool_name,
                    params=params,
                    package_evaluation=fresh_package_resolution.evaluation,
                    policy_action=composed["queue_observed_package"],
                    scanner_evidence=fresh_scanner_evidence,
                )
            executed_action = composed["executed_action"]
            response, observe_event = self._record_package_forward(
                message=message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                artifact=artifact,
                artifact_hash=fresh_package_resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                policy_action=executed_action,
                package_evaluation=fresh_package_resolution.evaluation,
                scanner_evidence=(*fresh_scanner_evidence, *composed["evidence_append"]),
                event_decision=executed_action,
                remember=False,
                policy_workspace=fresh_package_resolution.policy_workspace,
                decision_source="policy-observe",
                expected_catalog_generation=expected_catalog_generation,
                expected_catalog_state=expected_catalog_state,
                expected_catalog_fingerprint=expected_catalog_fingerprint,
            )
            final_observe_event = {**observe_event, "decision": executed_action, "observe_mode": True}
            if composed["observe_override"]:
                final_observe_event.update(
                    {
                        "observed_policy_action": composed["observed_policy_action"],
                        "observed_tool_policy_action": composed["observed_tool_policy_action"],
                        "observed_package_policy_action": composed["observed_package_policy_action"],
                    }
                )
            return response, final_observe_event
        if compose_kind != "proceed":
            raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_compose_unknown")

        authoritative_action = composed["authoritative_action"]
        if composed["pending_claims"]:
            pending_tool = fresh_tool_decision.pending_approval_reuse_decision
            pending_package = fresh_package_resolution.pending_approval_reuse_decision
            pending_claims = tuple(claim for claim in (pending_tool, pending_package) if claim is not None)
            try:
                catalog_current = self._drain_and_validate_catalog_authority(
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                    generation=expected_catalog_generation,
                    state=expected_catalog_state,
                    fingerprint=expected_catalog_fingerprint,
                )
            except Exception:
                self._poison_tools_catalog()
                catalog_current = False
            if not catalog_current:
                return self._catalog_boundary_failure_response(
                    message_id=message.get("id"),
                    tool_name=tool_name,
                    params=params,
                    scanner_evidence=fresh_scanner_evidence,
                    phase="before_saved_approval_claim",
                    package_request=True,
                )
            if not self.store.claim_approval_reuse_decisions(pending_claims, now=_now()):
                return self._queue_package_approval_response(
                    message_id=message.get("id"),
                    artifact=artifact,
                    artifact_hash=fresh_package_resolution.artifact_digest,
                    tool_name=tool_name,
                    params=params,
                    package_evaluation=fresh_package_resolution.evaluation,
                    policy_action="require-reapproval",
                    scanner_evidence=(*fresh_scanner_evidence, self._native_evidence_item("claim_failed")),
                )
            try:
                fresh_config = self._claim_boundary_config()
            except Exception:
                return self._queue_package_approval_response(
                    message_id=message.get("id"),
                    artifact=artifact,
                    artifact_hash=fresh_package_resolution.artifact_digest,
                    tool_name=tool_name,
                    params=params,
                    package_evaluation=fresh_package_resolution.evaluation,
                    policy_action="require-reapproval",
                    scanner_evidence=(*fresh_scanner_evidence, self._native_evidence_item("config_refresh_failed")),
                )
            self.config = fresh_config
            postclaim = self._package_postclaim(
                message=message,
                tool_name=tool_name,
                params=params,
                artifact=artifact,
                tool_artifact=tool_artifact,
                tool_artifact_hash=tool_artifact_hash,
                fresh_tool_decision=fresh_tool_decision,
                fresh_package_resolution=fresh_package_resolution,
            )
            if not isinstance(postclaim, _PostclaimForward):
                return postclaim
            authoritative_action = postclaim.authoritative_action
            artifact = postclaim.artifact
            fresh_package_resolution = postclaim.resolution
            fresh_scanner_evidence = postclaim.scanner_evidence
            expected_catalog_generation = postclaim.catalog_generation
            expected_catalog_state = postclaim.catalog_state
            expected_catalog_fingerprint = postclaim.catalog_fingerprint
        bound_request = _bound_external_archive_mcp_request(
            message,
            params,
            evaluation=fresh_package_resolution.evaluation,
        )
        if bound_request is None:
            try:
                binding_failure = package_external_archive_override(
                    fresh_package_resolution.evaluation,
                    variant="mcp_unbound",
                )
                return self._terminal_package_response(
                    message_id=message.get("id"),
                    artifact=artifact,
                    artifact_hash=fresh_package_resolution.artifact_digest,
                    tool_name=tool_name,
                    params=params,
                    package_evaluation=binding_failure,
                    policy_action="block",
                    scanner_evidence=fresh_scanner_evidence,
                )
            finally:
                _cleanup_external_archive_downloads(fresh_package_resolution.evaluation)
        bound_message, bound_params = bound_request
        try:
            return self._record_package_forward(
                message=bound_message,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                artifact=artifact,
                artifact_hash=fresh_package_resolution.artifact_digest,
                tool_name=tool_name,
                params=bound_params,
                policy_action=authoritative_action,
                package_evaluation=fresh_package_resolution.evaluation,
                scanner_evidence=fresh_scanner_evidence,
                event_decision=f"package-{authoritative_action}",
                remember=remember_allow and remember_decision_source is not None,
                policy_workspace=fresh_package_resolution.policy_workspace,
                decision_source=remember_decision_source or f"policy-{authoritative_action}",
                expected_catalog_generation=expected_catalog_generation,
                expected_catalog_state=expected_catalog_state,
                expected_catalog_fingerprint=expected_catalog_fingerprint,
                receipt_signals=remember_signals,
                receipt_risk_categories=remember_risk_categories,
            )
        finally:
            _cleanup_external_archive_downloads(fresh_package_resolution.evaluation)

    def _package_postclaim(
        self,
        *,
        message: dict[str, Any],
        tool_name: str,
        params: dict[str, Any],
        artifact: Any,
        tool_artifact: Any,
        tool_artifact_hash: str,
        fresh_tool_decision: ToolCallDecision,
        fresh_package_resolution: _PackagePolicyResolution,
    ) -> tuple[dict[str, Any], dict[str, Any]] | _PostclaimForward:
        """Revalidate a package request after its saved approvals were claimed.

        Returns a rendered response tuple, or a ``_PostclaimForward`` when the
        resident found the claimed authority still covers the request.
        """

        claimed_tool_decision = fresh_tool_decision.pending_approval_reuse_decision
        claimed_tool_disposition = fresh_tool_decision.approval_reuse_claim_disposition
        claimed_package_decision = fresh_package_resolution.pending_approval_reuse_decision
        claimed_package_disposition = fresh_package_resolution.approval_reuse_claim_disposition
        authority = self._resolve_tool_call_authority(tool_name=tool_name, arguments=params.get("arguments"))
        postclaim_package_artifact = self._package_request_artifact(
            tool_name=tool_name,
            arguments=params.get("arguments"),
        )
        tool_decision = authority.decision
        resolved: dict[str, _PackagePolicyResolution] = {}

        def package_facts_need(_need: Mapping[str, Any]) -> dict[str, object]:
            resolution = self._resolve_package_policy(
                artifact=postclaim_package_artifact,
                external_archive_network_authorized=True,
            )
            resolved["package"] = resolution
            return {
                "package": {
                    "facts": package_facts(resolution),
                    "artifact_id": (
                        postclaim_package_artifact.artifact_id if postclaim_package_artifact is not None else None
                    ),
                    "expected_artifact_id": artifact.artifact_id,
                    "digest": resolution.artifact_digest,
                    "expected_digest": fresh_package_resolution.artifact_digest,
                    "tool_claim_authorizes_review": bool(
                        claimed_approval_authorizes_postclaim_review(
                            claim_disposition=claimed_tool_disposition,
                            claimed_decision=claimed_tool_decision,
                            current_decision=tool_decision.pending_approval_reuse_decision,
                            guard_home=self.store.guard_home,
                        )
                    ),
                    "package_claim_authorizes_review": bool(
                        claimed_approval_authorizes_postclaim_review(
                            claim_disposition=claimed_package_disposition,
                            claimed_decision=claimed_package_decision,
                            current_decision=resolution.pending_approval_reuse_decision,
                            guard_home=self.store.guard_home,
                        )
                    ),
                }
            }

        try:
            outcome = self._native_decide(
                {
                    "check": "package_postclaim",
                    "tool": tool_facts(tool_decision),
                    "tool_context": {
                        "artifact_id": authority.artifact.artifact_id,
                        "expected_artifact_id": tool_artifact.artifact_id,
                        "artifact_hash": authority.artifact_hash,
                        "expected_artifact_hash": tool_artifact_hash,
                    },
                    "package_artifact_present": postclaim_package_artifact is not None,
                },
                supply={"postclaim_package": package_facts_need},
            )
        except BaseException:
            if "package" in resolved:
                _cleanup_external_archive_downloads(resolved["package"].evaluation)
            raise
        resolution = resolved.get("package")
        try:
            return self._render_package_postclaim(
                outcome,
                message=message,
                tool_name=tool_name,
                params=params,
                authority=authority,
                tool_decision=tool_decision,
                postclaim_package_artifact=postclaim_package_artifact,
                resolution=resolution,
            )
        except BaseException:
            if resolution is not None:
                _cleanup_external_archive_downloads(resolution.evaluation)
            raise
        finally:
            if resolution is not None and outcome["disposition"]["kind"] != "forward":
                _cleanup_external_archive_downloads(resolution.evaluation)

    def _render_package_postclaim(
        self,
        outcome: Mapping[str, Any],
        *,
        message: dict[str, Any],
        tool_name: str,
        params: dict[str, Any],
        authority: _ToolCallAuthority,
        tool_decision: ToolCallDecision,
        postclaim_package_artifact: Any | None,
        resolution: _PackagePolicyResolution | None,
    ) -> tuple[dict[str, Any], dict[str, Any]] | _PostclaimForward:
        disposition = outcome["disposition"]
        kind = disposition["kind"]
        tool_evidence = (
            *_tool_decision_scanner_evidence(tool_decision),
            *outcome.get("tool_evidence_append", ()),
        )
        if kind == "stored_tool_block":
            return self._stored_tool_block_response(
                message_id=message.get("id"),
                artifact=authority.artifact,
                artifact_hash=authority.artifact_hash,
                tool_name=tool_name,
                params=params,
                signals=tool_decision.signals,
                risk_categories=tool_decision.risk_categories,
                scanner_evidence=tool_evidence,
                package_request=True,
            )
        if kind == "terminal_tool":
            return self._terminal_tool_response(
                message_id=message.get("id"),
                artifact=authority.artifact,
                artifact_hash=authority.artifact_hash,
                tool_name=tool_name,
                params=params,
                policy_action=disposition["policy_action"],
                signals=tool_decision.signals,
                risk_categories=tool_decision.risk_categories,
                scanner_evidence=tool_evidence,
            )
        if kind == "queue_tool":
            return self._queue_approval_center_response(
                message_id=message.get("id"),
                artifact=authority.artifact,
                artifact_hash=authority.artifact_hash,
                tool_name=tool_name,
                signals=tool_decision.signals,
                params=params,
                scanner_evidence=tool_evidence,
                policy_action="require-reapproval",
            )
        if resolution is None or postclaim_package_artifact is None:
            raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_postclaim_unbound")
        package_evidence = (
            *self._package_scanner_evidence(
                resolution=resolution,
                tool_evidence=_tool_decision_scanner_evidence(tool_decision),
            ),
            *outcome.get("package_evidence_append", ()),
        )
        if kind == "stored_package_block":
            return self._stored_package_block_response(
                message_id=message.get("id"),
                artifact=postclaim_package_artifact,
                artifact_hash=resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=resolution.evaluation,
                scanner_evidence=package_evidence,
            )
        if kind == "terminal_package":
            return self._terminal_package_response(
                message_id=message.get("id"),
                artifact=postclaim_package_artifact,
                artifact_hash=resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=resolution.evaluation,
                policy_action=disposition["policy_action"],
                scanner_evidence=package_evidence,
            )
        if kind == "queue_package":
            return self._queue_package_approval_response(
                message_id=message.get("id"),
                artifact=postclaim_package_artifact,
                artifact_hash=resolution.artifact_digest,
                tool_name=tool_name,
                params=params,
                package_evaluation=resolution.evaluation,
                policy_action="require-reapproval",
                scanner_evidence=package_evidence,
            )
        if kind != "forward":
            raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_disposition_unknown")
        return _PostclaimForward(
            authoritative_action=disposition["authoritative_action"],
            artifact=postclaim_package_artifact,
            resolution=resolution,
            scanner_evidence=package_evidence,
            catalog_generation=authority.catalog_generation,
            catalog_state=authority.catalog_state,
            catalog_fingerprint=authority.catalog_fingerprint,
        )

    @staticmethod
    def _package_scanner_evidence(
        *,
        resolution: _PackagePolicyResolution,
        tool_evidence: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, object], ...]:
        package_context = resolution.execution_context
        context_evidence = (
            (cast(dict[str, object], package_context.to_evidence()),) if package_context is not None else ()
        )
        reuse_evidence = tuple(
            {"source": "approval_reuse", **cast(dict[str, object], raw)}
            for reason in resolution.evaluation.reasons
            if isinstance(reason, Mapping) and isinstance((raw := reason.get("approval_reuse")), dict)
        )
        return (*tool_evidence, *context_evidence, *reuse_evidence)

    def _record_package_forward(
        self,
        *,
        message: dict[str, Any],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        policy_action: GuardAction,
        package_evaluation: Any,
        scanner_evidence: tuple[dict[str, object], ...],
        event_decision: str,
        remember: bool,
        policy_workspace: str | None,
        decision_source: str,
        expected_catalog_generation: int,
        expected_catalog_state: _ToolCatalogState,
        expected_catalog_fingerprint: str,
        receipt_signals: tuple[str, ...] = (),
        receipt_risk_categories: tuple[str, ...] = (),
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        reason_signals = tuple(
            str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons
        )
        if remember:
            allow_tool_call(
                store=self.store,
                artifact=artifact,
                artifact_hash=artifact_hash,
                decision_source=decision_source,
                now=_now(),
                signals=receipt_signals or reason_signals,
                risk_categories=receipt_risk_categories,
                remember=True,
                arguments=_safe_mcp_arguments(params.get("arguments")),
                policy_workspace=policy_workspace,
                additional_scanner_evidence=scanner_evidence,
                policy_action=policy_action,
                emit_runtime_evidence=False,
            )
        try:
            response = self._forward_message(
                message,
                child_stdin,
                child_stdout,
                client_input=client_input,
                server_output=server_output,
                expected_catalog_generation=expected_catalog_generation,
                expected_catalog_state=expected_catalog_state,
                expected_catalog_fingerprint=expected_catalog_fingerprint,
            )
        except _ToolCatalogBoundaryChangedError:
            return self._catalog_boundary_failure_response(
                message_id=message.get("id"),
                tool_name=tool_name,
                params=params,
                scanner_evidence=scanner_evidence,
                phase="immediately_before_forward",
                package_request=True,
            )
        allow_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source=decision_source,
            now=_now(),
            signals=receipt_signals or reason_signals,
            risk_categories=receipt_risk_categories,
            remember=False,
            arguments=_safe_mcp_arguments(params.get("arguments")),
            policy_workspace=policy_workspace,
            additional_scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )
        return response, {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "timeout" if _is_timeout_response(response) else event_decision,
            "policy_action": policy_action,
            "redacted_params": _safe_mcp_params(params),
            "scanner_evidence": list(scanner_evidence),
        }

    def _queue_observed_package_request(
        self,
        *,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        package_evaluation: Any,
        policy_action: GuardAction,
        scanner_evidence: tuple[dict[str, object], ...],
    ) -> None:
        decision_v2_payload = self._package_decision_v2(package_evaluation, policy_action)
        self._queue_observed_approval_requests(
            artifact=artifact,
            artifact_hash=artifact_hash,
            tool_name=tool_name,
            params=params,
            policy_action=policy_action,
            risk_summary=package_evaluation.risk_summary,
            risk_signals=[str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons],
            decision_v2_payload=decision_v2_payload,
            extra_fields={
                "changed_fields": ["runtime_tool_call", "package_request"],
                "scanner_evidence": list(scanner_evidence),
                "supply_chain_evaluation": package_evaluation.to_dict(),
            },
        )

    @staticmethod
    def _package_decision_v2(package_evaluation: Any, policy_action: GuardAction) -> dict[str, Any]:
        payload = build_decision_v2(
            policy_action,
            reason=policy_action,
            signals=_package_reason_signals(package_evaluation.reasons),
        ).to_dict()
        payload["user_title"] = package_evaluation.user_copy.title
        payload["user_body"] = package_evaluation.user_copy.summary
        payload["harness_message"] = package_evaluation.user_copy.harness_message
        payload["dashboard_primary_detail"] = package_evaluation.user_copy.summary
        return payload

    def _queue_package_approval_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        package_evaluation: Any,
        policy_action: GuardAction,
        scanner_evidence: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        decision_v2_payload = self._package_decision_v2(package_evaluation, policy_action)
        risk_signals = tuple(str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons)
        if not asks_for_approval(self.config):
            response, event = self._queue_approval_center_response(
                message_id=message_id,
                artifact=artifact,
                artifact_hash=artifact_hash,
                tool_name=tool_name,
                params=params,
                signals=(package_evaluation.risk_summary, *risk_signals),
                scanner_evidence=scanner_evidence,
                policy_action=policy_action,
            )
            evaluation_payload = deepcopy(package_evaluation.to_dict())
            evaluation_payload["decision"] = "block"
            evaluation_payload["policy_action"] = "block"
            user_copy = evaluation_payload.setdefault("user_copy", {})
            user_copy.update(
                title="Package request blocked",
                summary=package_evaluation.risk_summary,
                dashboard_url=None,
                next_step=response["error"]["message"],
                harness_message=response["error"]["message"],
            )
            response["error"]["data"]["supplyChainEvaluation"] = evaluation_payload
            return response, event
        approval_center_url = ensure_guard_daemon(self.context.guard_home)
        queued = queue_blocked_approvals(
            redaction_level=self.config.receipt_redaction_level,
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
                        "changed_fields": ["runtime_tool_call", "package_request"],
                        "policy_action": policy_action,
                        "launch_target": self._launch_target(tool_name, params.get("arguments")),
                        "risk_summary": package_evaluation.risk_summary,
                        "risk_signals": list(risk_signals),
                        "decision_v2_json": decision_v2_payload,
                        "scanner_evidence": list(scanner_evidence),
                        "supply_chain_evaluation": package_evaluation.to_dict(),
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
            signals=risk_signals,
            arguments=_safe_mcp_arguments(params.get("arguments")),
            additional_scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )
        request_id = str(queued[0]["request_id"]) if queued else "unknown"
        review_url = first_approval_url(queued, approval_center_url=approval_center_url) or approval_center_url
        self._maybe_open_approval_center(
            approval_center_url=approval_center_url,
            review_url=review_url,
            open_key=request_id,
        )
        response_data = {
            "approvalCenterUrl": approval_center_url,
            "approvalRequests": queued,
            "guardPolicyAction": policy_action,
            "reviewUrl": review_url,
            "supplyChainEvaluation": package_evaluation.to_dict(),
        }
        return _blocked_tool_response(
            message_id,
            tool_name,
            (
                f"HOL Guard stopped package install request {tool_name} from {self.server_name}. "
                f"Approve request {request_id} at {review_url}, then retry the same action."
            ),
            response_data,
        ), {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "queue-package-approval",
            "policy_action": policy_action,
            "redacted_params": _safe_mcp_params(params),
            "approval_center_url": approval_center_url,
            "approval_requests": queued,
            "review_url": review_url,
            "scanner_evidence": list(scanner_evidence),
        }

    def _terminal_tool_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        policy_action: GuardAction,
        signals: tuple[str, ...],
        risk_categories: tuple[str, ...],
        scanner_evidence: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        block_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source="policy-block",
            now=_now(),
            signals=signals,
            risk_categories=risk_categories,
            arguments=_safe_mcp_arguments(params.get("arguments")),
            additional_scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )
        reason = (
            f"HOL Guard blocked tool call {tool_name} from {self.server_name}."
            if policy_action == "block"
            else (
                f"HOL Guard requires an enforceable sandbox for tool call {tool_name} from "
                f"{self.server_name}; this runtime cannot provide one."
            )
        )
        response = _blocked_tool_response(
            message_id,
            tool_name,
            reason,
            {"approvalRequests": [], "guardPolicyAction": policy_action},
        )
        event: dict[str, Any] = {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": f"terminal-{policy_action}",
            "policy_action": policy_action,
            "redacted_params": _safe_mcp_params(params),
            "approval_requests": [],
        }
        if scanner_evidence:
            event["scanner_evidence"] = list(scanner_evidence)
        return response, event

    def _record_package_block(
        self,
        *,
        artifact: Any,
        artifact_hash: str,
        params: dict[str, Any],
        package_evaluation: Any,
        scanner_evidence: tuple[dict[str, object], ...],
        policy_action: GuardAction,
    ) -> None:
        reason_signals = tuple(
            str(item.get("message") or item.get("code") or "") for item in package_evaluation.reasons
        )
        block_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source="policy-block",
            now=_now(),
            signals=reason_signals,
            arguments=_safe_mcp_arguments(params.get("arguments")),
            additional_scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )

    def _terminal_package_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        package_evaluation: Any,
        policy_action: GuardAction,
        scanner_evidence: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._record_package_block(
            artifact=artifact,
            artifact_hash=artifact_hash,
            params=params,
            package_evaluation=package_evaluation,
            scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )
        reason = (
            f"HOL Guard blocked package install request {tool_name} from {self.server_name}."
            if policy_action == "block"
            else (
                f"HOL Guard requires an enforceable sandbox for package install request {tool_name} from "
                f"{self.server_name}; this runtime cannot provide one."
            )
        )
        response = _blocked_tool_response(
            message_id,
            tool_name,
            reason,
            {
                "approvalRequests": [],
                "guardPolicyAction": policy_action,
                "supplyChainEvaluation": package_evaluation.to_dict(),
            },
        )
        return response, {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": f"terminal-package-{policy_action}",
            "policy_action": policy_action,
            "redacted_params": _safe_mcp_params(params),
            "approval_requests": [],
            "scanner_evidence": list(scanner_evidence),
        }

    def _stored_tool_block_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        signals: tuple[str, ...],
        risk_categories: tuple[str, ...],
        scanner_evidence: tuple[dict[str, object], ...],
        package_request: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        block_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source="policy-block",
            now=_now(),
            signals=signals,
            risk_categories=risk_categories,
            arguments=_safe_mcp_arguments(params.get("arguments")),
            additional_scanner_evidence=scanner_evidence,
            policy_action="block",
        )
        request_kind = "package tool call" if package_request else "tool call"
        response = _blocked_tool_response(
            message_id,
            tool_name,
            (
                f"HOL Guard blocked {request_kind} {tool_name} from {self.server_name}. "
                "This exact request is already blocked by authenticated saved policy."
            ),
            {
                "approvalRequests": [],
                "guardPolicyAction": "block",
            },
        )
        event: dict[str, Any] = {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "block-stored-policy",
            "policy_action": "block",
            "redacted_params": _safe_mcp_params(params),
            "approval_requests": [],
        }
        if scanner_evidence:
            event["scanner_evidence"] = list(scanner_evidence)
        return response, event

    def _stored_package_block_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        package_evaluation: Any,
        scanner_evidence: tuple[dict[str, object], ...],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._record_package_block(
            artifact=artifact,
            artifact_hash=artifact_hash,
            params=params,
            package_evaluation=package_evaluation,
            scanner_evidence=scanner_evidence,
            policy_action="block",
        )
        response = _blocked_tool_response(
            message_id,
            tool_name,
            (
                f"HOL Guard blocked package install request {tool_name} from {self.server_name}. "
                "This exact request is already blocked by stored policy with authenticated local integrity."
            ),
            {
                "approvalRequests": [],
                "guardPolicyAction": "block",
                "supplyChainEvaluation": package_evaluation.to_dict(),
            },
        )
        return response, {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "package-block-stored",
            "policy_action": "block",
            "redacted_params": _safe_mcp_params(params),
            "approval_requests": [],
            "scanner_evidence": list(scanner_evidence),
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
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        artifact: Any,
        artifact_hash: str,
        decision_source: str,
        signals: tuple[str, ...],
        risk_categories: tuple[str, ...],
        params: dict[str, Any],
        expected_catalog_generation: int | None = None,
        expected_catalog_state: _ToolCatalogState | None = None,
        expected_catalog_fingerprint: str | None = None,
        remember: bool = False,
        scanner_evidence: tuple[dict[str, object], ...] = (),
        policy_action: GuardAction = "allow",
        approval_decision: ToolCallDecision | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        pending = approval_decision.pending_approval_reuse_decision if approval_decision is not None else None
        claim_disposition = (
            approval_decision.approval_reuse_claim_disposition if approval_decision is not None else None
        )
        if pending is not None:
            if (
                expected_catalog_generation is None
                or expected_catalog_state is None
                or expected_catalog_fingerprint is None
            ):
                return self._catalog_boundary_failure_response(
                    message_id=message.get("id"),
                    tool_name=str(params.get("name") or artifact.name),
                    params=params,
                    scanner_evidence=scanner_evidence,
                    phase="missing_saved_approval_boundary",
                    package_request=False,
                )
            try:
                catalog_current = self._drain_and_validate_catalog_authority(
                    child_stdin=child_stdin,
                    child_stdout=child_stdout,
                    client_input=client_input,
                    server_output=server_output,
                    generation=expected_catalog_generation,
                    state=expected_catalog_state,
                    fingerprint=expected_catalog_fingerprint,
                )
            except Exception:
                self._poison_tools_catalog()
                catalog_current = False
            if not catalog_current:
                return self._catalog_boundary_failure_response(
                    message_id=message.get("id"),
                    tool_name=str(params.get("name") or artifact.name),
                    params=params,
                    scanner_evidence=scanner_evidence,
                    phase="before_saved_approval_claim",
                    package_request=False,
                )
            if not self.store.claim_approval_reuse_decisions((pending,), now=_now()):
                failed_evidence = (*scanner_evidence, self._native_evidence_item("claim_failed"))
                return self._queue_approval_center_response(
                    message_id=message.get("id"),
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    tool_name=str(params.get("name") or artifact.name),
                    signals=signals,
                    params=params,
                    scanner_evidence=failed_evidence,
                    policy_action="require-reapproval",
                )

            tool_name = str(params.get("name") or artifact.name)
            try:
                fresh_config = self._claim_boundary_config()
            except Exception:
                return self._queue_approval_center_response(
                    message_id=message.get("id"),
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    tool_name=tool_name,
                    signals=signals,
                    params=params,
                    scanner_evidence=(*scanner_evidence, self._native_evidence_item("config_refresh_failed")),
                    policy_action="require-reapproval",
                )
            self.config = fresh_config
            arguments = params.get("arguments")
            fresh_authority = self._resolve_tool_call_authority(
                tool_name=tool_name,
                arguments=arguments,
                config=fresh_config,
            )
            expected_catalog_generation = fresh_authority.catalog_generation
            expected_catalog_state = fresh_authority.catalog_state
            expected_catalog_fingerprint = fresh_authority.catalog_fingerprint
            fresh_decision = fresh_authority.decision
            claim_authorizes_review = claimed_approval_authorizes_postclaim_review(
                claim_disposition=claim_disposition,
                claimed_decision=pending,
                current_decision=fresh_decision.pending_approval_reuse_decision,
                guard_home=self.store.guard_home,
            )

            def reapproval_allowed(_need: Mapping[str, Any]) -> dict[str, object]:
                return {
                    "fresh_claim_allows_reapproval": bool(
                        fresh_claim_allows_reapproval(
                            claim_disposition=claim_disposition,
                            reason_code=fresh_decision.approval_reuse_reason_code,
                            decision=pending,
                            artifact=fresh_authority.artifact,
                            artifact_hash=fresh_authority.artifact_hash,
                            guard_home=self.store.guard_home,
                        )
                    )
                }

            postclaim = self._native_decide(
                {
                    "check": "tool_postclaim",
                    "fresh": tool_facts(fresh_decision),
                    "artifact_id": fresh_authority.artifact.artifact_id,
                    "expected_artifact_id": artifact.artifact_id,
                    "artifact_hash": fresh_authority.artifact_hash,
                    "expected_artifact_hash": artifact_hash,
                    "claim_authorizes_review": bool(claim_authorizes_review),
                },
                supply={"fresh_claim_allows_reapproval": reapproval_allowed},
            )
            postclaim_evidence = (
                *_tool_decision_scanner_evidence(fresh_decision),
                *postclaim["evidence_append"],
            )
            disposition = postclaim["disposition"]
            if disposition["kind"] == "stored_block":
                return self._stored_tool_block_response(
                    message_id=message.get("id"),
                    artifact=fresh_authority.artifact,
                    artifact_hash=fresh_authority.artifact_hash,
                    tool_name=tool_name,
                    params=params,
                    signals=fresh_decision.signals,
                    risk_categories=fresh_decision.risk_categories,
                    scanner_evidence=postclaim_evidence,
                    package_request=False,
                )
            if disposition["kind"] == "terminal":
                return self._terminal_tool_response(
                    message_id=message.get("id"),
                    artifact=fresh_authority.artifact,
                    artifact_hash=fresh_authority.artifact_hash,
                    tool_name=tool_name,
                    params=params,
                    policy_action=disposition["policy_action"],
                    signals=fresh_decision.signals,
                    risk_categories=fresh_decision.risk_categories,
                    scanner_evidence=postclaim_evidence,
                )
            if disposition["kind"] == "queue_reapproval":
                return self._queue_approval_center_response(
                    message_id=message.get("id"),
                    artifact=fresh_authority.artifact,
                    artifact_hash=fresh_authority.artifact_hash,
                    tool_name=tool_name,
                    signals=fresh_decision.signals,
                    params=params,
                    scanner_evidence=postclaim_evidence,
                    policy_action=disposition["policy_action"],
                )
            if disposition["kind"] != "forward":
                raise NativeMcpProxyDecisionError("native_mcp_proxy_decision_disposition_unknown")
            # The resident found the claimed authority still covers the fresh
            # identity. Carry the fresh identity and risk material into the
            # final receipt and forward.
            artifact = fresh_authority.artifact
            artifact_hash = fresh_authority.artifact_hash
            signals = fresh_decision.signals
            risk_categories = fresh_decision.risk_categories
            scanner_evidence = postclaim_evidence
        if remember:
            try:
                allow_tool_call(
                    store=self.store,
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    decision_source=decision_source,
                    now=_now(),
                    signals=signals,
                    risk_categories=risk_categories,
                    remember=True,
                    arguments=_safe_mcp_arguments(params.get("arguments")),
                    additional_scanner_evidence=scanner_evidence,
                    policy_action=policy_action,
                    emit_runtime_evidence=False,
                )
            except ApprovalGateError:
                return self._queue_approval_center_response(
                    message_id=message.get("id"),
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    tool_name=str(params.get("name") or artifact.name),
                    signals=signals,
                    params=params,
                    scanner_evidence=scanner_evidence,
                    policy_action="require-reapproval",
                )
        try:
            response = self._forward_message(
                message,
                child_stdin,
                child_stdout,
                client_input=client_input,
                server_output=server_output,
                expected_catalog_generation=expected_catalog_generation,
                expected_catalog_state=expected_catalog_state,
                expected_catalog_fingerprint=expected_catalog_fingerprint,
            )
        except _ToolCatalogBoundaryChangedError:
            return self._catalog_boundary_failure_response(
                message_id=message.get("id"),
                tool_name=str(params.get("name") or artifact.name),
                params=params,
                scanner_evidence=scanner_evidence,
                phase="immediately_before_forward",
                package_request=False,
            )
        allow_tool_call(
            store=self.store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            decision_source=decision_source,
            now=_now(),
            signals=signals,
            risk_categories=risk_categories,
            remember=False,
            arguments=_safe_mcp_arguments(params.get("arguments")),
            additional_scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )
        event: dict[str, Any] = {
            "method": "tools/call",
            "tool_name": params.get("name"),
            "decision": "timeout" if _is_timeout_response(response) else decision_source,
            "policy_action": policy_action,
            "redacted_params": _safe_mcp_params(params),
        }
        if scanner_evidence:
            event["scanner_evidence"] = list(scanner_evidence)
        return response, event

    @staticmethod
    def _forward_notification(message: dict[str, Any], child_stdin: IO[str] | _NativeMcpChildIo) -> None:
        child_stdin.write(json.dumps(message) + "\n")
        child_stdin.flush()

    def _next_child_output_frame(
        self,
        child_stdout: IO[str] | _NativeMcpChildIo,
        *,
        timeout_seconds: float,
        required: bool,
    ) -> _ChildOutputFrame | None:
        if isinstance(child_stdout, _NativeMcpChildIo):
            # Drain the resident-path injection buffer first so synthesized
            # frames (post-claim notifications in tests) are observed before
            # the next real child frame.
            injected = self._child_output_queue
            if injected is not None:
                try:
                    return injected.get_nowait()
                except queue.Empty:
                    pass
            return child_stdout.next_frame(timeout_seconds, required)
        output_queue = self._child_output_queue if child_stdout is self._active_child_stdout else None
        if output_queue is not None:
            try:
                if required:
                    return output_queue.get(timeout=timeout_seconds)
                if timeout_seconds > 0:
                    return output_queue.get(timeout=timeout_seconds)
                return output_queue.get_nowait()
            except queue.Empty as exc:
                if required:
                    raise ProxyIoTimeoutError(
                        source="child_response",
                        timeout_seconds=timeout_seconds,
                    ) from exc
                return None

        if not required and isinstance(child_stdout, io.StringIO):
            if child_stdout.tell() >= len(child_stdout.getvalue()):
                return None
            return _ChildOutputFrame(line=child_stdout.readline())
        try:
            line = _readline_with_timeout(
                child_stdout,
                timeout_seconds,
                source="child_response",
                allow_background_wait=required,
            )
        except ProxyIoTimeoutError:
            if required:
                raise
            return None
        return _ChildOutputFrame(line=line)

    @staticmethod
    def _child_output_line(frame: _ChildOutputFrame) -> str:
        if frame.error is not None:
            raise frame.error
        if frame.line is None or not frame.line:
            raise RuntimeError("Guard stdio proxy did not receive a response from the MCP server.")
        return frame.line

    def _multiplex_child_payload(
        self,
        payload: dict[str, Any],
        *,
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
    ) -> None:
        method = str(payload.get("method", ""))
        if method in {"notifications/tools/list_changed", "tools/list_changed"}:
            self._invalidate_tools_catalog()
        if _is_request(payload):
            self._proxy_child_request(
                payload=payload,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
            )
            return
        if "id" in payload:
            self._buffer_child_response(payload)
            return
        if server_output is not None:
            server_output.write(json.dumps(payload) + "\n")
            server_output.flush()

    def _drain_child_messages(
        self,
        *,
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        quiet_seconds: float = 0.0,
    ) -> None:
        """Multiplex every queued child frame and wait for an optional quiet edge."""

        while True:
            frame = self._next_child_output_frame(
                child_stdout,
                timeout_seconds=quiet_seconds,
                required=False,
            )
            if frame is None:
                return
            line = self._child_output_line(frame)
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                self._poison_tools_catalog()
                raise
            if not isinstance(payload, dict):
                self._poison_tools_catalog()
                raise RuntimeError("Guard runtime MCP proxy received a non-object child payload.")
            self._multiplex_child_payload(
                payload,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
            )

    def _catalog_authority_matches(
        self,
        *,
        generation: int,
        state: _ToolCatalogState,
        fingerprint: str,
    ) -> bool:
        return (
            generation == self._tool_catalog_generation
            and state == self._tool_catalog_state
            and fingerprint
            == _tool_catalog_fingerprint(
                self._tool_catalog,
                state=self._tool_catalog_state,
            )
        )

    def _drain_and_validate_catalog_authority(
        self,
        *,
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        client_input: TextIO | None,
        server_output: TextIO | None,
        generation: int,
        state: _ToolCatalogState,
        fingerprint: str,
        quiet_seconds: float = 0.0,
    ) -> bool:
        self._drain_child_messages(
            child_stdin=child_stdin,
            child_stdout=child_stdout,
            client_input=client_input,
            server_output=server_output,
            quiet_seconds=quiet_seconds,
        )
        return self._catalog_authority_matches(
            generation=generation,
            state=state,
            fingerprint=fingerprint,
        )

    def _forward_message(
        self,
        message: dict[str, Any],
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
        *,
        client_input: TextIO | None,
        server_output: TextIO | None,
        expected_catalog_generation: int | None = None,
        expected_catalog_state: _ToolCatalogState | None = None,
        expected_catalog_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        request_id = message.get("id")
        if (
            str(message.get("method", "")) == "tools/call"
            and expected_catalog_generation is not None
            and expected_catalog_state is not None
            and expected_catalog_fingerprint is not None
            and not self._drain_and_validate_catalog_authority(
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
                generation=expected_catalog_generation,
                state=expected_catalog_state,
                fingerprint=expected_catalog_fingerprint,
                quiet_seconds=_TOOLS_CALL_PREWRITE_QUIET_SECONDS,
            )
        ):
            raise _ToolCatalogBoundaryChangedError(_TOOL_CATALOG_EXECUTION_BOUNDARY_CHANGED)
        child_stdin.write(json.dumps(message) + "\n")
        child_stdin.flush()
        while True:
            buffered_response = self._pop_buffered_child_response(request_id)
            if buffered_response is not None:
                return buffered_response
            timeout_seconds = self._child_response_timeout_seconds()
            try:
                frame = self._next_child_output_frame(
                    child_stdout,
                    timeout_seconds=timeout_seconds,
                    required=True,
                )
            except ProxyIoTimeoutError:
                active_process = self._active_process
                if active_process is not None:
                    _quarantine_process(active_process)
                return _timeout_response(
                    request_id,
                    source="child_response",
                    timeout_seconds=timeout_seconds,
                    message="Guard runtime MCP proxy timed out waiting for the MCP server.",
                )
            assert frame is not None
            # The native stdio session returns a timeout as a frame ``error``
            # rather than raising. Mirror the ``except ProxyIoTimeoutError``
            # branch above so both transports yield the same
            # ``_timeout_response`` and quarantine the child.
            if isinstance(frame.error, ProxyIoTimeoutError):
                active_process = self._active_process
                if active_process is not None:
                    _quarantine_process(active_process)
                return _timeout_response(
                    request_id,
                    source="child_response",
                    timeout_seconds=timeout_seconds,
                    message="Guard runtime MCP proxy timed out waiting for the MCP server.",
                )
            line = self._child_output_line(frame)
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise RuntimeError("Guard runtime MCP proxy received a non-object child payload.")
            if payload.get("id") == request_id and not _is_request(payload):
                return payload
            self._multiplex_child_payload(
                payload,
                child_stdin=child_stdin,
                child_stdout=child_stdout,
                client_input=client_input,
                server_output=server_output,
            )

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
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
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
            timeout_seconds = self._nested_request_timeout_seconds()
            try:
                line = _readline_with_timeout(
                    client_input,
                    timeout_seconds,
                    source="nested_client_response",
                    allow_background_wait=False,
                )
            except ProxyIoTimeoutError:
                self._forward_notification(
                    _timeout_response(
                        request_id,
                        source="nested_client_response",
                        timeout_seconds=timeout_seconds,
                        message="Guard runtime MCP proxy timed out waiting for the client response.",
                    ),
                    child_stdin,
                )
                return
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
        child_stdin: IO[str] | _NativeMcpChildIo,
        child_stdout: IO[str] | _NativeMcpChildIo,
    ) -> dict[str, Any]:
        request_id = request.get("id")
        output_stream.write(json.dumps(request) + "\n")
        output_stream.flush()
        while True:
            buffered_response = self._pop_buffered_client_response(request_id)
            if buffered_response is not None:
                return _approval_payload(buffered_response)
            timeout_seconds = self._inline_approval_timeout_seconds()
            try:
                line = _readline_with_timeout(
                    input_stream,
                    timeout_seconds,
                    source="inline_approval",
                    allow_background_wait=False,
                )
            except ProxyIoTimeoutError:
                return {"action": "cancel", "reason": "timeout"}
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

    def _build_artifact_payload(
        self,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        signals: tuple[str, ...],
        *,
        policy_action: str = "require-reapproval",
        scanner_evidence: tuple[dict[str, object], ...] = (),
    ) -> dict[str, Any]:
        """Build the artifact payload for approval center queueing.

        Includes browser intent metadata when the MCP tool call is a browser
        automation call (HGBM063-HGBM065).
        """
        arguments = params.get("arguments")
        launch_target, browser_intent_dict = _browser_intent_payload(
            artifact,
            arguments,
            default_launch_target=self._launch_target(tool_name, arguments),
        )
        changed_fields: list[str] = ["runtime_tool_call"]

        if browser_intent_dict is not None:
            changed_fields.append("runtime_browser_tool_call")

        payload: dict[str, Any] = {
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact.artifact_type,
            "source_scope": artifact.source_scope,
            "config_path": artifact.config_path,
            "changed_fields": changed_fields,
            "policy_action": policy_action,
            "launch_target": launch_target,
            "risk_summary": tool_call_risk_summary(artifact, arguments),
            "risk_signals": list(signals),
        }
        if browser_intent_dict is not None:
            payload["browser_intent"] = browser_intent_dict
        if scanner_evidence:
            payload["scanner_evidence"] = list(scanner_evidence)
        return payload

    def _queue_approval_center_response(
        self,
        *,
        message_id: Any,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        signals: tuple[str, ...],
        params: dict[str, Any],
        scanner_evidence: tuple[dict[str, object], ...] = (),
        policy_action: GuardAction = "require-reapproval",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not asks_for_approval(self.config):
            block_tool_call(
                store=self.store,
                artifact=artifact,
                artifact_hash=artifact_hash,
                decision_source="policy-safe-alternative",
                now=_now(),
                signals=signals,
                risk_categories=tool_call_risk_categories(artifact, params.get("arguments")),
                arguments=_safe_mcp_arguments(params.get("arguments")),
                additional_scanner_evidence=scanner_evidence,
                policy_action=policy_action,
            )
            from ..approvals import record_unprompted_review

            record_unprompted_review(
                detection=HarnessDetection(
                    harness=self.harness,
                    installed=True,
                    command_available=True,
                    config_paths=(self.config_path,),
                    artifacts=(artifact,),
                ),
                evaluation={
                    "artifacts": [
                        self._build_artifact_payload(
                            artifact,
                            artifact_hash,
                            tool_name,
                            params,
                            signals,
                            policy_action=policy_action,
                            scanner_evidence=scanner_evidence,
                        )
                    ]
                },
                store=self.store,
                redaction_level=self.config.receipt_redaction_level,
            )
            return _blocked_tool_response(
                message_id,
                tool_name,
                safe_alternative_reason(
                    f"HOL Guard blocked tool call {tool_name} from {self.server_name}. " + " ".join(signals)
                ),
                {"approvalRequests": [], "guardPolicyAction": "block", "transportOutcome": "not-forwarded"},
            ), {
                "method": "tools/call",
                "tool_name": tool_name,
                "decision": "safe-alternative",
                "policy_action": policy_action,
                "approval_requests": [],
                "prompted": False,
                "redacted_params": _safe_mcp_params(params),
            }
        approval_center_url = ensure_guard_daemon(self.context.guard_home)
        queued = queue_blocked_approvals(
            redaction_level=self.config.receipt_redaction_level,
            detection=HarnessDetection(
                harness=self.harness,
                installed=True,
                command_available=True,
                config_paths=(self.config_path,),
                artifacts=(artifact,),
            ),
            evaluation={
                "artifacts": [
                    self._build_artifact_payload(
                        artifact,
                        artifact_hash,
                        tool_name,
                        params,
                        signals,
                        policy_action=policy_action,
                        scanner_evidence=scanner_evidence,
                    ),
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
            arguments=_safe_mcp_arguments(params.get("arguments")),
            additional_scanner_evidence=scanner_evidence,
            policy_action=policy_action,
        )
        request_id = str(queued[0]["request_id"]) if queued else "unknown"
        review_url = first_approval_url(queued, approval_center_url=approval_center_url) or approval_center_url
        self._maybe_open_approval_center(
            approval_center_url=approval_center_url,
            review_url=review_url,
            open_key=request_id,
        )
        response_data = {
            "approvalCenterUrl": approval_center_url,
            "approvalRequests": queued,
            "guardPolicyAction": policy_action,
            "reviewUrl": review_url,
        }
        response = _blocked_tool_response(
            message_id,
            tool_name,
            (
                f"HOL Guard stopped tool call {tool_name} from {self.server_name}. "
                f"Approve request {request_id} at {review_url}, then retry the same action."
            ),
            response_data,
        )
        queued_event: dict[str, Any] = {
            "method": "tools/call",
            "tool_name": tool_name,
            "decision": "queue-approval",
            "policy_action": policy_action,
            "redacted_params": _safe_mcp_params(params),
            "approval_center_url": approval_center_url,
            "approval_requests": queued,
            "review_url": review_url,
        }
        if scanner_evidence:
            queued_event["scanner_evidence"] = list(scanner_evidence)
        return response, queued_event

    def _queue_observed_approval_requests(
        self,
        *,
        artifact: Any,
        artifact_hash: str,
        tool_name: str,
        params: dict[str, Any],
        policy_action: str,
        risk_summary: str,
        risk_signals: list[str],
        decision_v2_payload: dict[str, Any] | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if policy_action not in {"review", "block", "sandbox-required", "require-reapproval"}:
            return []
        approval_center_url = ensure_guard_daemon(self.context.guard_home)
        launch_target, browser_intent_dict = _browser_intent_payload(
            artifact,
            params.get("arguments"),
            default_launch_target=self._launch_target(tool_name, params.get("arguments")),
        )
        artifact_payload: dict[str, Any] = {
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_hash": artifact_hash,
            "artifact_type": artifact.artifact_type,
            "source_scope": artifact.source_scope,
            "config_path": artifact.config_path,
            "changed_fields": ["runtime_tool_call"],
            "policy_action": policy_action,
            "launch_target": launch_target,
            "risk_summary": risk_summary,
            "risk_signals": risk_signals,
        }
        # Include browser intent metadata when present
        if browser_intent_dict is not None:
            artifact_payload["changed_fields"].append("runtime_browser_tool_call")
            artifact_payload["browser_intent"] = browser_intent_dict
        if decision_v2_payload is not None:
            artifact_payload["decision_v2_json"] = decision_v2_payload
        if extra_fields:
            artifact_payload.update(extra_fields)
        return queue_blocked_approvals(
            redaction_level=self.config.receipt_redaction_level,
            detection=HarnessDetection(
                harness=self.harness,
                installed=True,
                command_available=True,
                config_paths=(self.config_path,),
                artifacts=(artifact,),
            ),
            evaluation={"artifacts": [artifact_payload]},
            store=self.store,
            approval_center_url=approval_center_url,
            now=_now(),
        )

    def _catalog_state_fact(self) -> dict[str, object]:
        pending = self._tool_catalog_pending
        return {
            "state": self._tool_catalog_state,
            "generation": self._tool_catalog_generation,
            "inflight": self._tool_catalog_inflight,
            "inflight_cursor": self._tool_catalog_inflight_cursor,
            "expected_cursor": self._tool_catalog_expected_cursor,
            "catalog_names": sorted(self._tool_catalog),
            "pending_names": None if pending is None else sorted(pending),
        }

    def _catalog_unavailable(self) -> None:
        """Fail closed when the resident cannot answer a catalog event.

        This only records that no authoritative catalog exists; it never
        computes a transition. The ``error`` state authorizes nothing.
        """

        self._tool_catalog_state = "error"
        self._tool_catalog = {}
        self._tool_catalog_pending = None
        self._tool_catalog_expected_cursor = None
        self._tool_catalog_inflight = False
        self._tool_catalog_inflight_cursor = None
        self._tool_catalog_generation += 1

    def _catalog_event(self, event: dict[str, object]) -> dict[str, Any] | None:
        """Apply one resident-decided catalog transition to the mirrored state."""

        try:
            payload = self._native_decide(
                {"check": "catalog_event", "state": self._catalog_state_fact(), "event": event}
            )
            state = payload["state"]
            pool = {**self._tool_catalog, **(self._tool_catalog_pending or {}), **(payload.get("page") or {})}
            catalog = {name: pool[name] for name in payload["catalog_names"]}
            pending_names = payload["pending_names"]
            pending = None if pending_names is None else {name: pool[name] for name in pending_names}
            applied = (
                state["state"],
                state["generation"],
                state["inflight"],
                state["inflight_cursor"],
                state["expected_cursor"],
            )
        except (NativeMcpProxyDecisionError, KeyError, TypeError):
            self._catalog_unavailable()
            return None
        (
            self._tool_catalog_state,
            self._tool_catalog_generation,
            self._tool_catalog_inflight,
            self._tool_catalog_inflight_cursor,
            self._tool_catalog_expected_cursor,
        ) = applied
        self._tool_catalog = catalog
        self._tool_catalog_pending = pending
        return payload

    def _reset_tools_catalog_unobserved(self) -> None:
        self._catalog_event({"kind": "reset"})

    def _poison_tools_catalog(self) -> None:
        self._catalog_event({"kind": "poison"})

    def _invalidate_tools_catalog(self) -> None:
        self._catalog_event({"kind": "invalidate"})

    def _begin_tools_catalog_request(
        self,
        request_cursor: object | None,
        *,
        advance_root_generation: bool = True,
    ) -> int:
        """Start one validated root or continuation request and return its generation."""

        payload = self._catalog_event(
            {
                "kind": "begin",
                "cursor": cursor_fact(request_cursor),
                "advance_root_generation": advance_root_generation,
            }
        )
        if payload is None:
            return self._tool_catalog_generation
        return int(payload["request_generation"])

    def _fail_tools_catalog_request(self, request_generation: int) -> None:
        self._catalog_event({"kind": "fail", "request_generation": request_generation})

    def _capture_tools_catalog(
        self,
        response: dict[str, Any],
        *,
        request_cursor: object | None = None,
        request_generation: int | None = None,
    ) -> None:
        self._catalog_event(
            {
                "kind": "capture",
                "cursor": cursor_fact(request_cursor),
                "request_generation": request_generation,
                "response": response,
            }
        )

    @staticmethod
    def _launch_target(tool_name: str, arguments: object) -> str:
        from ..native_context import context_mcp_arguments_projection

        _safe, launch_target, _digest = context_mcp_arguments_projection(tool_name, arguments)
        return launch_target


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


class CursorMcpGuardProxy(ElicitationMcpGuardProxy):
    """Guard-managed runtime MCP proxy for Cursor editor MCP clients."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(harness="cursor", **kwargs)


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


def _inline_approval_kind(payload: object) -> str:
    """Classify an inline approval reply for the resident; it decides what follows."""

    if _approval_allows(payload):
        return "allow"
    if _approval_denies(payload) or _approval_invalid(payload):
        return "denied"
    return "fallthrough"


def _approval_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "result" in payload:
        result = payload.get("result")
        return result if isinstance(result, dict) else {"action": "cancel"}
    if "error" in payload:
        return {"action": "cancel"}
    return {"action": "cancel"}


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


def _has_saved_package_block(reasons: Sequence[object]) -> bool:
    return any(isinstance(reason, Mapping) and reason.get("code") == "saved_package_block" for reason in reasons)


def _package_reason_signals(reasons: Sequence[object]) -> tuple[RiskSignalV2, ...]:
    signals: list[RiskSignalV2] = []
    for reason in reasons:
        if not isinstance(reason, Mapping):
            continue
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


def _package_signal_severity(value: str | None) -> RiskSeverityLabel:
    match value:
        case "info":
            return "info"
        case "low":
            return "low"
        case "medium":
            return "medium"
        case "high":
            return "high"
        case "critical":
            return "critical"
        case _:
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
    "CursorMcpGuardProxy",
    "ElicitationMcpGuardProxy",
    "OpenCodeMcpGuardProxy",
    "RuntimeMcpGuardProxy",
]
