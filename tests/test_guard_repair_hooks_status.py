"""Hook repair must not report success when reinstalling leaves an app broken."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import repair_engine
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import install_commands
from codex_plugin_scanner.guard.store import GuardStore


def _setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, still_broken: set[str]
) -> tuple[HarnessContext, GuardStore]:
    home = tmp_path / "home"
    home.mkdir()
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")
    store = GuardStore(context.guard_home, prime_policy_integrity=False)
    reinstalled: list[str] = []

    def fake_install(_action: str, harness: str, *_args: object) -> None:
        reinstalled.append(harness)

    def fake_broken(_context: HarnessContext, _store: GuardStore) -> list[dict[str, object]]:
        names = ["codex", "claude-code"] if not reinstalled else sorted(still_broken)
        return [{"harness": name, "setup_status": "broken"} for name in names]

    monkeypatch.setattr(install_commands, "apply_managed_install", fake_install)
    monkeypatch.setattr(repair_engine, "broken_hook_harnesses", fake_broken)
    return context, store


def test_hooks_that_stay_broken_after_reinstall_are_skipped_not_repaired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, store = _setup(tmp_path, monkeypatch, still_broken={"codex", "claude-code"})

    step = repair_engine.repair_hooks(context, store, dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    assert step["status"] == "skipped"
    assert step["repaired"] == []
    assert step["needs_attention"] == ["codex", "claude-code"]
    assert report["status"] == "partial"
    assert "still need attention" in str(report["summary"])
    assert "Guard was repaired" not in str(report["summary"])


def test_mixed_outcome_reports_changed_and_names_remaining_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context, store = _setup(tmp_path, monkeypatch, still_broken={"codex"})

    step = repair_engine.repair_hooks(context, store, dry_run=False)

    assert step["status"] == "changed"
    assert step["repaired"] == ["claude-code"]
    assert step["needs_attention"] == ["codex"]
    assert "Still needs attention: codex" in str(step["summary"])
    report = repair_engine.build_report([step], dry_run=False)
    assert report["status"] == "partial"
    assert "Guard was repaired" not in str(report["summary"])


def test_fully_repaired_hooks_still_report_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context, store = _setup(tmp_path, monkeypatch, still_broken=set())

    step = repair_engine.repair_hooks(context, store, dry_run=False)

    assert step["status"] == "changed"
    assert step["repaired"] == ["codex", "claude-code"]
    assert step["needs_attention"] == []
