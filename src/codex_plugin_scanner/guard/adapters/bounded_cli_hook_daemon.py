"""Daemon fast path for the bounded CLI hook bridge."""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from ..daemon.auth_token import load_guard_daemon_auth_token as _read_daemon_auth_token
from ..private_file_io import read_private_regular_text
from .bounded_cli_hook_envelope import _event_name, _json_object
from .bounded_cli_hook_failure import failure_payload, grok_observe_event
from .bounded_hook_http import post_hook_json, prepare_grok_prompt

_MAX_HOOK_RESPONSE_BYTES = 1_000_000
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_DAEMON_TIMEOUT_BUDGET_SECONDS = 5.0


def _assert_loopback_http_url(url: str) -> None:
    """Reject non-loopback daemon URLs."""
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise ValueError(f"daemon URL must use http, not {parsed.scheme!r}")
    if parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError(f"daemon URL must target loopback, not {parsed.hostname!r}")


def _build_loopback_opener() -> urllib.request.OpenerDirector:
    """Build an opener that blocks proxies and off-loopback redirects."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _LoopbackOnlyRedirectHandler(),
    )


class _LoopbackOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        _assert_loopback_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _daemon_hook_endpoint(guard_home: Path, harness: str) -> str | None:
    """Return the loopback hook URL from authenticated daemon state, or None."""
    raw_state = read_private_regular_text(
        guard_home / "daemon-state.json",
        max_bytes=64 * 1024,
        require_private_parent=True,
    )
    if raw_state is None:
        return None
    origin = daemon_state_origin(raw_state)
    return None if origin is None else f"{origin}/v1/hooks/{harness}"


def daemon_state_origin(raw_state: str) -> str | None:
    """The loopback origin a published daemon state names, or None.

    A cleared (``{}``) or malformed state names no daemon.
    """
    try:
        state = json.loads(raw_state)
    except json.JSONDecodeError:
        return None
    if not isinstance(state, dict):
        return None
    host = state.get("host")
    port = state.get("port")
    if (
        not isinstance(host, str)
        or host not in _LOOPBACK_HOSTS
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
    ):
        return None
    rendered_host = f"[{host}]" if host == "::1" else host
    return f"http://{rendered_host}:{port}"


def _rendered_bridge_answer(
    parsed: dict[str, object],
    *,
    harness: str,
    event_name: str,
    guard_home: Path,
    deadline: float,
) -> tuple[str, str, int]:
    """What the harness reads for the daemon's answer, rendered by the resident.

    A resident that cannot render it leaves the fixed fail-closed payload for
    this harness and event, as an unreachable daemon would.
    """
    if harness.strip().lower().replace("_", "-") == "muse":
        from .muse_hook_render import apply_muse_pretool_approval_wait, muse_bridge_response

        answer: dict[str, object] = dict(parsed)
        try:
            from ..config import load_guard_config
            from ..store import GuardStore

            remaining = max(0, int(deadline - time.monotonic()))
            configured = load_guard_config(guard_home).approval_wait_timeout_seconds
            wait_seconds = min(configured, remaining)
            if wait_seconds > 0:
                answer = apply_muse_pretool_approval_wait(
                    answer,
                    event_name=event_name,
                    store=GuardStore(guard_home),
                    timeout_seconds=wait_seconds,
                )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, sqlite3.Error):
            answer = dict(parsed)
        return muse_bridge_response(answer, event_name=event_name, guard_home=guard_home, deadline=deadline)
    from ..native_hook_render import native_cli_hook_emit

    rendered = native_cli_hook_emit(
        harness, parsed, event_name=event_name, guard_home=guard_home, deadline=deadline, bridge=True
    )
    if rendered is not None:
        stdout = rendered.get("stdout")
        stderr = rendered.get("stderr")
        exit_code = rendered.get("exit_code")
        if (
            isinstance(stdout, str)
            and isinstance(stderr, str)
            and isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
        ):
            return stdout, stderr, exit_code
    payload, exit_code = failure_payload(
        harness=harness,
        event_name=event_name,
        reason="HOL Guard could not read the daemon's answer to this hook.",
        recording_only=False,
    )
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")), "", exit_code


def _apply_grok_bridge_approval_wait(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    timeout_seconds: float | None = None,
) -> tuple[str, str, int]:
    """Wait for Grok review after a fast daemon decision, inside the hook budget."""
    if harness.strip().lower() != "grok" or _event_name(input_text) != "PreToolUse":
        return stdout, stderr, exit_code
    payload = _json_object(stdout)
    if payload is None:
        return stdout, stderr, exit_code
    if str(payload.get("policy_action") or "") not in {"review", "require-reapproval"}:
        return stdout, stderr, exit_code
    try:
        from ..config import load_guard_config
        from ..store import GuardStore
        from .grok_approval_resume import apply_grok_pretool_approval_wait

        configured = load_guard_config(guard_home).approval_wait_timeout_seconds
        wait_seconds = configured
        if timeout_seconds is not None:
            wait_seconds = min(configured, max(0, int(timeout_seconds)))
        updated = apply_grok_pretool_approval_wait(
            payload,
            event_name="PreToolUse",
            store=GuardStore(guard_home),
            timeout_seconds=wait_seconds,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, sqlite3.Error):
        return stdout, stderr, exit_code
    rewritten = json.dumps(updated, ensure_ascii=True, separators=(",", ":")) + "\n"
    if updated.get("decision") == "allow":
        return rewritten, stderr, 0
    return rewritten, stderr, exit_code


def try_daemon_hook(
    *,
    guard_home: Path,
    harness: str,
    input_text: str,
    timeout_seconds: float,
    deadline_monotonic: float | None = None,
    _endpoint_loader: Callable[[Path, str], str | None] | None = None,
    _token_loader: Callable[[Path], str | None] | None = None,
    _opener_builder: Callable[[], urllib.request.OpenerDirector] | None = None,
) -> tuple[str, str, int] | None:
    """POST the hook payload to the running daemon; return native stdout or None."""
    started = time.monotonic()
    from .hook_http_deadline import deadline_http_handler

    deadline = started + timeout_seconds if deadline_monotonic is None else deadline_monotonic
    if started >= deadline:
        return None
    endpoint = (_endpoint_loader or _daemon_hook_endpoint)(guard_home, harness)
    if endpoint is None or time.monotonic() >= deadline:
        return None
    try:
        _assert_loopback_http_url(endpoint)
    except ValueError:
        return None
    token = (_token_loader or _read_daemon_auth_token)(guard_home)
    if token is None or time.monotonic() >= deadline:
        return None
    event_name = _event_name(input_text)
    prompt_event = event_name == "UserPromptSubmit"
    grok_prompt = prompt_event and harness.strip().lower().replace("_", "-") == "grok"
    timeout = min(float(timeout_seconds) * 0.5, 10.0 if prompt_event else _DAEMON_TIMEOUT_BUDGET_SECONDS)
    if grok_observe_event(harness, _event_name(input_text)):
        timeout = min(timeout, 1.0)
    transport_deadline = min(deadline, time.monotonic() + timeout)
    timeout = transport_deadline - time.monotonic()
    if timeout <= 0:
        return None
    try:
        opener = (_opener_builder or _build_loopback_opener)()
        if isinstance(opener, urllib.request.OpenerDirector):
            opener.add_handler(deadline_http_handler(transport_deadline))
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        return None
    if grok_prompt:
        prepared_input = prepare_grok_prompt(
            endpoint,
            token,
            input_text,
            opener=opener,
            deadline=transport_deadline,
            max_bytes=_MAX_HOOK_RESPONSE_BYTES,
        )
        if prepared_input is None:
            return None
        input_text = prepared_input
    parsed = post_hook_json(
        endpoint,
        token,
        input_text.encode("utf-8"),
        opener=opener,
        deadline=transport_deadline,
        max_bytes=_MAX_HOOK_RESPONSE_BYTES,
    )
    if parsed is None:
        return None
    if harness.strip().lower().replace("_", "-") == "hermes":
        from .hermes_runtime_hooks import hermes_bridge_response

        # Render within what is left of the hook's own budget, not a fresh timeout.
        return hermes_bridge_response(parsed, event_name=event_name, guard_home=guard_home, deadline=deadline)
    return _rendered_bridge_answer(
        parsed,
        harness=harness.strip().lower().replace("_", "-"),
        event_name=event_name,
        guard_home=guard_home,
        deadline=deadline,
    )


__all__ = ["daemon_state_origin", "try_daemon_hook"]
