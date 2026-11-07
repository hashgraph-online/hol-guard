from __future__ import annotations

import sys
import threading
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import cli as guard_cli
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer

FACADE = "codex_plugin_scanner.guard.cli.commands_support_hook_payload"


def _wait_for_warm_thread() -> None:
    deadline = time.monotonic() + 5
    while any(thread.name == "codex-live-decision-warm" for thread in threading.enumerate()):
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_daemon_loads_the_live_decision_facade_before_the_first_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, FACADE, raising=False)
    monkeypatch.delattr(guard_cli, "commands_support_hook_payload", raising=False)
    events: list[str] = []
    owner = SimpleNamespace(_diagnostics=SimpleNamespace(record_exception=events.append))

    GuardDaemonServer._warm_codex_live_decision(owner)  # type: ignore[arg-type]
    _wait_for_warm_thread()

    assert FACADE in sys.modules
    assert events == []


def test_a_failed_warm_up_is_recorded_and_left_to_the_request_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, FACADE, None)
    monkeypatch.delattr(guard_cli, "commands_support_hook_payload", raising=False)
    events: list[str] = []
    owner = SimpleNamespace(_diagnostics=SimpleNamespace(record_exception=events.append))

    GuardDaemonServer._warm_codex_live_decision(owner)  # type: ignore[arg-type]
    _wait_for_warm_thread()

    assert events == ["codex_live_decision_warmup_failed"]
