from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok_config import (
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
    GUARD_HOOK_PRETOOL_FILE,
)
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.update_grok_repair import repair_grok_install
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    guard_home = home / ".hol-guard"
    guard_home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _seed_grok_install(context: HarnessContext, store: GuardStore, now: str) -> Path:
    adapter = GrokHarnessAdapter()
    manifest = adapter.install(context)
    store.set_managed_install("grok", True, None, manifest, now)
    return adapter._hooks_dir(context) / GUARD_HOOK_PRETOOL_FILE


def _set_pretool_timeout(hook_path: Path, timeout: int) -> None:
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = timeout
    hook_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_grok_repair_skips_when_hooks_already_current(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    before = hook_path.read_text(encoding="utf-8")

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert repaired is None
    assert warning is None
    assert hook_path.read_text(encoding="utf-8") == before


def test_grok_repair_rewrites_stale_pretool_timeout(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    _set_pretool_timeout(hook_path, 30)

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert warning is None
    assert isinstance(repaired, dict)
    assert repaired.get("harness") == "grok"
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == GROK_PRETOOL_HOOK_TIMEOUT_SECONDS


def test_grok_repair_skips_inactive_install(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert repaired is None
    assert warning is None


def test_update_repair_rewrites_stale_grok_hooks(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    _set_pretool_timeout(hook_path, 30)

    repaired, notes = update_commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=None,
        now=now,
        dry_run=False,
    )

    assert notes == []
    assert any(item.get("harness") == "grok" for item in repaired)
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == GROK_PRETOOL_HOOK_TIMEOUT_SECONDS
