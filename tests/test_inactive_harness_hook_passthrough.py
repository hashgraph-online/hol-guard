"""Inactive or uninstalled apps must not fail-close leftover hooks."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.daemon.hook_worker_responses import prepare_native_hook_policy
from codex_plugin_scanner.guard.store import GuardStore

_PRE_TOOL_PAYLOAD: dict[str, object] = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Write",
    "command": "rm -rf /",
}


class _Handler:
    def __init__(self) -> None:
        self.payload: dict[str, object] | None = None

    def _write_json(self, payload: dict[str, object], status: int = 200) -> None:
        del status
        self.payload = payload

    def _runtime_hook_fail_safe_response(self, *_args: object, **kwargs: Any) -> dict[str, object]:
        return {
            "permission": "deny",
            "reason_code": kwargs.get("reason_code"),
            "reason": kwargs.get("reason"),
        }


def _daemon(
    *,
    managed: dict[str, object] | None,
    prepared: object = None,
    other_active: str | None = None,
) -> SimpleNamespace:
    def getter(_harness: str) -> dict[str, object] | None:
        return managed

    def lister() -> list[dict[str, object]]:
        installs: list[dict[str, object]] = []
        if isinstance(managed, dict):
            installs.append(managed)
        if other_active:
            installs.append({"harness": other_active, "active": True})
        return installs

    return SimpleNamespace(
        store=SimpleNamespace(
            get_managed_install=getter, list_managed_installs=lister, connection_scope=nullcontext
        ),
        hook_worker=SimpleNamespace(
            prepare_workspace_policy=lambda *_args, **_kwargs: prepared,
            metrics=SimpleNamespace(record_route=lambda *_args, **_kwargs: None),
            policy_snapshot_publisher=SimpleNamespace(last_error=None),
        ),
    )


def test_inactive_codex_hook_does_not_fail_closed_on_native_policy() -> None:
    handler = _Handler()

    def getter(name: str) -> dict[str, object] | None:
        if name == "codex":
            return {"harness": "codex", "active": False}
        if name == "cursor":
            return {"harness": "cursor", "active": True}
        return None

    daemon = SimpleNamespace(
        store=SimpleNamespace(get_managed_install=getter, connection_scope=nullcontext),
        hook_worker=SimpleNamespace(
            prepare_workspace_policy=lambda *_args, **_kwargs: None,
            metrics=SimpleNamespace(record_route=lambda *_args, **_kwargs: None),
            policy_snapshot_publisher=SimpleNamespace(last_error=None),
        ),
    )
    admitted = prepare_native_hook_policy(
        handler,
        daemon,
        dict(_PRE_TOOL_PAYLOAD),
        {"runtime-harness": ["cursor"]},
        "codex",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "harness_not_managed"


def test_never_installed_codex_hook_still_fail_closes_when_native_policy_is_not_ready() -> None:
    handler = _Handler()
    admitted = prepare_native_hook_policy(
        handler,
        _daemon(managed=None),
        dict(_PRE_TOOL_PAYLOAD),
        {},
        "codex",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "native_policy_not_ready"


def test_never_installed_codex_hook_passthrough_when_another_app_is_active() -> None:
    handler = _Handler()
    admitted = prepare_native_hook_policy(
        handler,
        _daemon(managed=None, other_active="cursor"),
        dict(_PRE_TOOL_PAYLOAD),
        {},
        "codex",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "harness_not_managed"


def test_runtime_harness_query_cannot_bypass_active_cursor_native_barrier() -> None:
    handler = _Handler()
    admitted = prepare_native_hook_policy(
        handler,
        _daemon(managed={"harness": "cursor", "active": True}),
        dict(_PRE_TOOL_PAYLOAD),
        {"runtime-harness": ["codex"]},
        "cursor",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "native_policy_not_ready"


def test_active_cursor_hook_still_fail_closes_when_native_policy_is_not_ready() -> None:
    handler = _Handler()
    admitted = prepare_native_hook_policy(
        handler,
        _daemon(managed={"harness": "cursor", "active": True}),
        dict(_PRE_TOOL_PAYLOAD),
        {},
        "cursor",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "native_policy_not_ready"


def test_managed_install_lookup_error_stays_fail_closed() -> None:
    handler = _Handler()

    def getter(_name: str) -> dict[str, object]:
        raise RuntimeError("managed install store unavailable")

    daemon = SimpleNamespace(
        store=SimpleNamespace(get_managed_install=getter, connection_scope=nullcontext),
        hook_worker=SimpleNamespace(
            prepare_workspace_policy=lambda *_args, **_kwargs: None,
            metrics=SimpleNamespace(record_route=lambda *_args, **_kwargs: None),
            policy_snapshot_publisher=SimpleNamespace(last_error=None),
        ),
    )
    admitted = prepare_native_hook_policy(
        handler,
        daemon,
        dict(_PRE_TOOL_PAYLOAD),
        {},
        "codex",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "native_policy_not_ready"


def test_inactive_claude_alias_passthrough_uses_canonical_managed_key() -> None:
    handler = _Handler()

    def getter(name: str) -> dict[str, object] | None:
        if name == "claude-code":
            return {"harness": "claude-code", "active": False}
        return None

    daemon = SimpleNamespace(
        store=SimpleNamespace(get_managed_install=getter, connection_scope=nullcontext),
        hook_worker=SimpleNamespace(
            prepare_workspace_policy=lambda *_args, **_kwargs: None,
            metrics=SimpleNamespace(record_route=lambda *_args, **_kwargs: None),
            policy_snapshot_publisher=SimpleNamespace(last_error=None),
        ),
    )
    admitted = prepare_native_hook_policy(
        handler,
        daemon,
        dict(_PRE_TOOL_PAYLOAD),
        {},
        "claude",
        None,
        0.0,
    )

    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "harness_not_managed"


def test_managed_harness_reads_observe_commits_between_reads_and_later_hooks(tmp_path: Path, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    writer = GuardStore(guard_home, prime_policy_integrity=False)
    daemon = _daemon(managed=None)
    daemon.store = store
    getter = store.get_managed_install
    mutation_done = False

    def get_then_activate_other(harness: str) -> dict[str, object] | None:
        nonlocal mutation_done
        managed = getter(harness)
        if not mutation_done:
            mutation_done = True
            # A different authority writer commits after the absent-row read.
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(writer.set_managed_install, "cursor", True, None, {}, "first").result(timeout=5)
        return managed

    monkeypatch.setattr(store, "get_managed_install", get_then_activate_other)
    if os.name != "nt":
        os.chmod(guard_home, 0o755)
        os.chmod(store.path, 0o644)
    handler = _Handler()
    admitted = prepare_native_hook_policy(handler, daemon, dict(_PRE_TOOL_PAYLOAD), {}, "codex", None, 0.0)
    assert admitted is False
    assert handler.payload is not None
    assert handler.payload.get("reason_code") == "harness_not_managed"
    if os.name != "nt":
        assert guard_home.stat().st_mode & 0o777 == 0o700
        assert store.path.stat().st_mode & 0o777 == 0o600

    writer.set_managed_install("codex", True, None, {}, "second")
    active_handler = _Handler()
    admitted = prepare_native_hook_policy(active_handler, daemon, dict(_PRE_TOOL_PAYLOAD), {}, "codex", None, 0.0)
    assert admitted is False
    assert active_handler.payload is not None
    assert active_handler.payload.get("reason_code") == "native_policy_not_ready"

    writer.set_managed_install("codex", False, None, {}, "third")
    inactive_handler = _Handler()
    admitted = prepare_native_hook_policy(inactive_handler, daemon, dict(_PRE_TOOL_PAYLOAD), {}, "codex", None, 0.0)
    assert admitted is False
    assert inactive_handler.payload is not None
    assert inactive_handler.payload.get("reason_code") == "harness_not_managed"
