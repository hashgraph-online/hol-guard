from __future__ import annotations

from codex_plugin_scanner.guard.cli import commands_router


def test_normalize_guard_handler_result_treats_none_as_success() -> None:
    assert commands_router._normalize_guard_handler_result(None) == 0
    assert commands_router._normalize_guard_handler_result(2) == 2
    assert commands_router._normalize_guard_handler_result({"status": "unexpected"}) == 1
