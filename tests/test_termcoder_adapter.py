"""Focused tests for the TermCoder harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import contract_for
from codex_plugin_scanner.guard.adapters.termcoder import (
    TERMCODER_GUARD_MARKER,
    TermCoderHarnessAdapter,
    termcoder_hook_payload,
)


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def test_termcoder_is_registered() -> None:
    assert isinstance(get_adapter("termcoder"), TermCoderHarnessAdapter)
    assert get_adapter("term-code").harness == "termcoder"
    assert "termcoder" in {adapter.harness for adapter in list_adapters()}
    assert contract_for("termcoder") is not None


def test_detects_termcoder_config(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config_path = ctx.home_dir / ".config" / "termcoder" / "config.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps({"mode": "build"}), encoding="utf-8")

    detection = TermCoderHarnessAdapter().detect(ctx)

    assert detection.installed is True
    assert str(config_path) in detection.config_paths
    assert detection.artifacts[0].artifact_type == "config"


def test_install_writes_independent_raw_pre_exec_contract(tmp_path: Path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.termcoder.install_guard_shim",
        lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-termcoder"), "notes": []},
    )

    manifest = TermCoderHarnessAdapter().install(ctx)

    guard_config = ctx.home_dir / ".config" / "termcoder" / "guard.json"
    payload = json.loads(guard_config.read_text(encoding="utf-8"))
    assert manifest["active"] is True
    assert payload["marker"] == TERMCODER_GUARD_MARKER
    assert payload["pre_exec"]["events"] == ["run", "build", "chat", "install", "uninstall"]
    assert "bounded_cli_hook_bridge" in payload["pre_exec"]["command"]
    assert "risk" not in json.dumps(payload).lower()


def test_hook_payload_preserves_raw_command_and_cwd() -> None:
    payload = termcoder_hook_payload(
        command="git commit -m 'keep the exact shell text'",
        cwd="/workspace/project",
        operation="build",
    )

    assert payload["tool_input"] == {"command": "git commit -m 'keep the exact shell text'"}
    assert payload["cwd"] == "/workspace/project"
    assert payload["termcoder_operation"] == "build"


def test_uninstall_removes_only_guard_config(tmp_path: Path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    adapter = TermCoderHarnessAdapter()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.termcoder.install_guard_shim",
        lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-termcoder"), "notes": []},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.termcoder.remove_guard_shim",
        lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-termcoder"), "notes": []},
    )

    adapter.install(ctx)
    adapter.uninstall(ctx)

    assert not (ctx.home_dir / ".config" / "termcoder" / "guard.json").exists()
