"""Native request contexts receive only the caller's routing facts."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_direct_tool_context as client


def test_caller_routing_environment_is_carried_without_unrelated_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BUN_OPTIONS", "--preload=synthetic.js")
    monkeypatch.setenv("NODE_OPTIONS", "--require=synthetic.js")
    monkeypatch.setenv("BASH_FUNC_synthetic%%", "synthetic function")
    monkeypatch.setenv("DYLD_SYNTHETIC", "synthetic loader")
    monkeypatch.setenv("UNRELATED_SYNTHETIC_SECRET", "must not travel")
    monkeypatch.setattr(client, "_process_groups", lambda: [123])
    facts = client._facts(tmp_path, tmp_path / "home")
    assert facts["environment"]["BUN_OPTIONS"] == "--preload=synthetic.js"
    assert facts["environment"]["NODE_OPTIONS"] == "--require=synthetic.js"
    assert "BASH_FUNC_synthetic%%" in facts["environment"]
    assert "DYLD_SYNTHETIC" in facts["environment"]
    assert "UNRELATED_SYNTHETIC_SECRET" not in facts["environment"]
    assert facts["groups"] == [123]
