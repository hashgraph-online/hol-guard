from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import cli as guard_cli
from codex_plugin_scanner.guard.daemon.live_decision_warmup import start_codex_live_decision_warmup

FACADE = "codex_plugin_scanner.guard.cli.commands_support_hook_payload"


def test_daemon_loads_the_live_decision_facade_before_the_first_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, FACADE, raising=False)
    monkeypatch.delattr(guard_cli, "commands_support_hook_payload", raising=False)
    events: list[str] = []

    start_codex_live_decision_warmup(SimpleNamespace(record_exception=events.append)).join(timeout=30)

    assert FACADE in sys.modules
    assert events == []


def test_a_failed_warm_up_is_recorded_and_left_to_the_request_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, FACADE, None)
    monkeypatch.delattr(guard_cli, "commands_support_hook_payload", raising=False)
    events: list[str] = []

    start_codex_live_decision_warmup(SimpleNamespace(record_exception=events.append)).join(timeout=30)

    assert events == ["codex_live_decision_warmup_failed"]
