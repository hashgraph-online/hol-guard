"""A failed hook answers without resolving paths or reading the store."""

from __future__ import annotations

from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import server as module


def test_fail_safe_response_spends_no_path_rpc_or_store_read() -> None:
    calls: list[object] = []

    class _Store:
        def __getattr__(self, name: str) -> object:
            calls.append(name)
            raise AssertionError(f"fail-safe response read the store: {name}")

    handler = SimpleNamespace(
        _optional_string=lambda value: value if isinstance(value, str) else None,
        _settled_hook_directories=lambda *args, **kwargs: calls.append((args, kwargs)),
        server=SimpleNamespace(store=_Store()),
    )
    result = module._GuardDaemonHandler._runtime_hook_fail_safe_response(
        handler,
        {"hook_event_name": "PreToolUse"},
        {"workspace": ["/tmp/project"], "home": ["/tmp/home"]},
        default_harness="codex",
        reason="HOL Guard could not complete the native hook decision safely.",
        reason_code="native_hook_worker_unavailable",
    )
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not calls
