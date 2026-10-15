"""Native CLI observer queueing."""

from __future__ import annotations

import queue
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_cli_observer as observer


def _payload(cwd: Path) -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": "npx wrangler whoami"}, "cwd": str(cwd)}


def _observe(cwd: Path) -> bool:
    return observer.observe_native_pre_tool_cli(object(), payload=_payload(cwd), workspace=cwd, home_dir=None)


def test_dropped_observation_is_not_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(observer, "_pending", queue.Queue(maxsize=1))
    monkeypatch.setattr(observer, "_recent", observer.OrderedDict())
    monkeypatch.setattr(observer, "_ensure_worker", lambda: None)
    observer._pending.put_nowait(("filler", "x", tmp_path, None))

    assert _observe(tmp_path) is False

    observer._pending.get_nowait()
    assert _observe(tmp_path) is True
    assert _observe(tmp_path) is False


def test_camel_case_harness_payload_is_observed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(observer, "_pending", queue.Queue(maxsize=4))
    monkeypatch.setattr(observer, "_recent", observer.OrderedDict())
    monkeypatch.setattr(observer, "_ensure_worker", lambda: None)
    payload = {
        "toolName": "run_terminal_command",
        "toolInput": {"command": "npx wrangler whoami"},
        "cwd": str(tmp_path),
    }

    assert observer.observe_native_pre_tool_cli(object(), payload=payload, workspace=tmp_path, home_dir=None) is True
