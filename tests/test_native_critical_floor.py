"""The encoded-payload consumer cannot weaken an absent native floor."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_critical_floor as client
from codex_plugin_scanner.guard.native_request_context import NativeRequestContextFailure


@pytest.mark.parametrize("action", ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"])
def test_presents_one_bound_native_floor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, action: str) -> None:
    calls: list[dict[str, Any]] = []

    def call(body: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        calls.append({"body": body, **kwargs})
        return {"kind": "critical_floor", "action": action}

    monkeypatch.setattr(client, "_call", call)
    assert client.native_critical_floor_action("hol-guard status", cwd=tmp_path, home_dir=tmp_path) == action
    assert len(calls) == 1
    assert calls[0]["body"] == {
        "kind": "critical_floor",
        "body": {"script": "hol-guard status", "cwd": str(tmp_path), "home_dir": str(tmp_path)},
    }
    assert calls[0]["source"] == "direct_command"
    assert calls[0]["budget_ms"] == 500


@pytest.mark.parametrize(
    "reply",
    [
        NativeRequestContextFailure("native_request_context_unavailable"),
        {},
        {"kind": "critical_floor", "action": True},
        {"kind": "critical_floor", "action": "unrecognized"},
        {"kind": "build", "action": "allow"},
        {"kind": "critical_floor", "action": "allow", "override": True},
    ],
)
def test_unavailable_or_malformed_floors_block(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: Any) -> None:
    monkeypatch.setattr(client, "_call", lambda *_args, **_kwargs: reply)
    assert client.native_critical_floor_action("hol-guard uninstall", cwd=tmp_path, home_dir=tmp_path) == "block"
