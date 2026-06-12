"""Integration tests for Grok managed protection and harness setup."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import setup_contract_for
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.cli.install_commands import (
    _grok_protection_checks,
    build_harness_setup_plan,
    build_harness_verification,
    uninstall_confirmation_token,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def test_uninstall_confirmation_token_for_grok() -> None:
    assert uninstall_confirmation_token("grok") == "disconnect-grok"


def test_setup_contract_includes_grok_connect_and_repair() -> None:
    contract = setup_contract_for("grok")
    assert contract is not None
    assert contract.display_name == "Grok"
    assert contract.setup_steps[0].command == ("hol-guard", "apps", "connect", "grok")
    assert contract.repair_steps[0].command == ("hol-guard", "apps", "repair", "grok")


def test_build_harness_setup_plan_disconnect_confirmation(tmp_path: Path) -> None:
    payload = build_harness_setup_plan("uninstall", "grok", _ctx(tmp_path), dry_run=False)
    assert payload["confirmation_phrase"] == "disconnect-grok"
    assert "hol-guard apps disconnect grok --confirm disconnect-grok" in str(payload["confirm_command"])


def test_grok_protection_checks_ready_after_install(tmp_path: Path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
        lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
    )
    GrokHarnessAdapter().install(ctx)
    (ctx.guard_home / "bin").mkdir(parents=True, exist_ok=True)
    (ctx.guard_home / "bin" / "guard-grok").write_text("#!/bin/sh\n", encoding="utf-8")
    checks = _grok_protection_checks(ctx)
    assert checks["pretool_hook_installed"] is True
    assert checks["prompt_hook_installed"] is True
    assert checks["managed_config_installed"] is True
    assert checks["ready"] is True


def test_build_harness_verification_includes_grok_checks(tmp_path: Path, monkeypatch) -> None:
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok.install_guard_shim",
        lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-grok"), "notes": []},
    )
    GrokHarnessAdapter().install(ctx)
    (ctx.guard_home / "bin").mkdir(parents=True, exist_ok=True)
    (ctx.guard_home / "bin" / "guard-grok").write_text("#!/bin/sh\n", encoding="utf-8")
    payload = build_harness_verification("grok", ctx)
    verification = payload["verification"]
    assert isinstance(verification, dict)
    assert verification.get("pretool_hook_installed") is True


def test_normalize_harness_payload_supports_grok_bash(tmp_path: Path) -> None:
    envelope = normalize_harness_payload(
        "grok",
        "PreToolUse",
        {
            "hookEventName": "pre_tool_use",
            "toolName": "run_terminal_command",
            "toolInput": {"command": "git diff README.md"},
        },
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )
    assert envelope.harness == "grok"
    assert envelope.action_type == "shell_command"
    assert envelope.command is not None
    assert "git diff" in envelope.command


def test_normalize_harness_payload_supports_grok_secret_read(tmp_path: Path) -> None:
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "grok" / "pretooluse_read_secret.json").read_text(encoding="utf-8")
    )
    envelope = normalize_harness_payload(
        "grok",
        "PreToolUse",
        fixture,
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )
    assert envelope.harness == "grok"
    assert envelope.action_type == "file_read"
    assert any(".env" in path for path in envelope.target_paths)
