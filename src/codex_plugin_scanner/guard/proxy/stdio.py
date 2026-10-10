"""Local stdio MCP proxy helpers."""

from __future__ import annotations

import io
import json
import os
import queue
import select
import subprocess
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast
from uuid import uuid4

from ..approvals import (
    approval_prompt_flow,
    build_approval_browser_url,
)
from ..browser_opener import open_browser_url
from ..config import GuardConfig
from ..daemon.manager import load_guard_daemon_auth_token
from ..native_execution import (
    _native_session_feature_available,
    mcp_stdio_session_close_native,
    mcp_stdio_session_open_native,
)
from ..runtime.approval_context import (
    build_configured_environment_hash,
    build_runtime_launch_identity,
    resolved_runtime_launch_executable,
    runtime_launch_identity_matches,
)
from ..runtime.surface_server import GuardSurfaceRuntime
from ..store import GuardStore
from ._env import _build_scrubbed_env
from .stdio_sensitive_read import evaluate_sensitive_read

if TYPE_CHECKING:
    from .runtime_mcp import _NativeChildProcess

_DEFAULT_PROXY_RESPONSE_TIMEOUT_SECONDS = 30.0
_PROXY_TERMINATION_TIMEOUT_SECONDS = 1.0
_GUARD_PROXY_TIMEOUT_ERROR_CODE = -32800


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


def _redact_json(value: Any) -> Any:
    """Redact recorded traffic for display; native authority only.

    The resident `mcp_redact_json` op owns the scalar/query/map-key fragment
    tables. A native failure is terminal — silent Python fallback could persist
    secrets unredacted.
    """
    from ..native_context import context_mcp_redact_json

    return context_mcp_redact_json(value)


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


class _ChildLifecycle(Protocol):
    """Lifecycle operations shared by native sessions and stdio children."""

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...


def _quarantine_process(process: _ChildLifecycle) -> None:
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
        if guard_store is not None:
            from ..native_context import bound_context_digest_home
            from ..native_policy_snapshot_publisher import ensure_native_launch_resident_verifier

            # A standalone stdio proxy never starts the snapshot publisher, so
            # it owns the same one-time verifier prerequisite before the
            # resident will serve `mcp_stdio_session_*`. A failure here must
            # raise: there is no Python fallback for the resident session.
            with bound_context_digest_home(getattr(guard_store, "guard_home", None)):
                ensure_native_launch_resident_verifier(guard_store)

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
            opener=open_browser_url,
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

    def _start_process(self) -> subprocess.Popen[str] | _NativeChildProcess:
        launch_env = _build_scrubbed_env(self.env)
        process: subprocess.Popen[str] | None = None
        native_session_id: str | None = None
        native_guard_home: Path | None = None
        # Assigned before the failure boundary so the cleanup path can name the
        # home a half-opened native session belongs to.
        guard_home = cast("Path | None", getattr(self.guard_store, "guard_home", None))
        try:
            # Digest calls raise when the native resident is unreachable; keep
            # them inside the failure boundary so partial state is unwound.
            self._active_launch_identity = self._build_launch_identity(launch_env)
            self._active_env_values_hash = build_configured_environment_hash(
                launch_env,
                configured_keys=tuple(self.env),
            )
            executable = resolved_runtime_launch_executable(self._active_launch_identity)
            # RTM-024: the resident owns the stdio child (spawn, framing,
            # teardown). argv is None when the launch identity did not yield a
            # verified executable, so the resident cannot take the child —
            # keep the Python pipe transport for that case only.
            argv = [executable] + [str(a) for a in self.command[1:]] if isinstance(executable, str) else None
            if argv is not None and guard_home is not None:
                native_session_id = f"stdio-{self.harness}-{os.getpid()}-{uuid4().hex[:8]}"
                native_guard_home = guard_home
                opened = mcp_stdio_session_open_native(
                    argv,
                    session_id=native_session_id,
                    home_dir=native_guard_home,
                    cwd=self.cwd,
                    extra_env=launch_env,
                    guard_home=native_guard_home,
                )
            else:
                opened = None
            if native_session_id is not None and opened is None and _native_session_feature_available():
                raise RuntimeError("Native stdio session authority is unavailable.")
            if opened is not None:
                if native_session_id is None or native_guard_home is None:
                    raise RuntimeError("Native stdio session authority is unavailable.")
                # Resident owns the child (RTM-024 data plane). A non-"opened"
                # status is terminal — never fall back to the Python transport
                # on a real open failure.
                if opened.get("status") != "opened":
                    raise RuntimeError(f"native stdio session open failed: {opened.get('payload')}")
                # Resident echoes the caller-supplied session id in `payload`
                # (same contract the runtime MCP proxy relies on). Keep our own
                # id and cross-check the echo rather than inventing a field the
                # result schema does not carry.
                if opened.get("payload") != native_session_id:
                    raise RuntimeError("native stdio session open returned an unexpected session id")
                if not self._active_launch_identity_matches(launch_env):
                    raise ProxyLaunchIdentityChangedError(
                        "Guard stdio proxy launch identity changed while starting the MCP server."
                    )
                from .runtime_mcp import _NativeChildProcess

                return _NativeChildProcess(native_session_id, native_guard_home)
            # The native open was not attempted or the session feature is
            # unsupported; only those cases may use the Python pipe transport.
            process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True,
                cwd=self.cwd,
                env=launch_env,
                executable=executable,
            )
            if not self._active_launch_identity_matches(launch_env):
                raise ProxyLaunchIdentityChangedError(
                    "Guard stdio proxy launch identity changed while starting the MCP server."
                )
            return process
        except BaseException:
            if process is not None:
                _quarantine_process(process)
            elif native_session_id is not None and native_guard_home is not None:
                mcp_stdio_session_close_native(native_session_id, guard_home=native_guard_home)
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
        process: subprocess.Popen[str] | _NativeChildProcess,
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
            not_forwarded = evaluate_sensitive_read(self, tool_name=tool_name, params=params, event=event)
            if not_forwarded is not None:
                response = _blocked_tool_response(message.get("id"), tool_name, *not_forwarded)
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
        process: subprocess.Popen[str] | _NativeChildProcess,
        message_id: Any,
        output_stream: Any | None = None,
    ) -> dict[str, Any] | None:
        if message_id is None:
            return None
        assert process.stdout is not None
        while True:
            timeout_seconds = self._response_timeout_seconds()
            try:
                from .runtime_mcp import _NativeMcpChildIo

                if isinstance(process.stdout, _NativeMcpChildIo):
                    # Native session (RTM-024): the resident already frames
                    # lines; ask it for the next one with the same timeout.
                    frame = process.stdout.next_frame(timeout_seconds, required=True)
                    if frame is None:
                        raise ProxyIoTimeoutError(source="child_response", timeout_seconds=timeout_seconds)
                    if frame.error is not None:
                        raise frame.error
                    line = frame.line
                else:
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
