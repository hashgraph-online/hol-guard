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
    assert "These still need attention: Harness hooks." in str(report["summary"])
    assert "Guard was repaired" not in str(report["summary"])
    # Nothing failed, so the run must not close by asking for another one.
    assert "Some steps failed" not in str(report["summary"])
    assert "No step failed, and another `hol-guard repair` run reaches the same answer." in str(report["summary"])


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
    assert "Some steps failed" not in str(report["summary"])


def test_fully_repaired_hooks_still_report_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context, store = _setup(tmp_path, monkeypatch, still_broken=set())

    step = repair_engine.repair_hooks(context, store, dry_run=False)

    assert step["status"] == "changed"
    assert step["repaired"] == ["codex", "claude-code"]
    assert step["needs_attention"] == []


def test_failed_post_reinstall_check_leaves_apps_unresolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context, store = _setup(tmp_path, monkeypatch, still_broken=set())
    calls: list[int] = []

    def flaky_broken(_context: HarnessContext, _store: GuardStore) -> list[dict[str, object]]:
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("store unavailable")
        return [{"harness": "codex", "setup_status": "broken"}, {"harness": "claude-code", "setup_status": "broken"}]

    monkeypatch.setattr(repair_engine, "broken_hook_harnesses", flaky_broken)

    step = repair_engine.repair_hooks(context, store, dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    assert step["status"] == "skipped"
    assert step["repaired"] == []
    assert step["needs_attention"] == ["codex", "claude-code"]
    assert report["status"] == "partial"


def test_a_failed_step_still_asks_for_another_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The advice that loops for an unsettled app is the right advice for a failure."""

    context, store = _setup(tmp_path, monkeypatch, still_broken={"codex"})

    def failing_install(_action: str, harness: str, *_args: object) -> None:
        raise RuntimeError("install blew up")

    monkeypatch.setattr(install_commands, "apply_managed_install", failing_install)
    step = repair_engine.repair_hooks(context, store, dry_run=False)
    report = repair_engine.build_report([step], dry_run=False)

    assert step["status"] == "error"
    assert "Some steps failed. Re-run `hol-guard repair`" in str(report["summary"])


def test_budget_exhausted_cleanup_still_asks_for_another_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A step that ran out of budget left work behind, even when another step waits on the user."""

    context, store = _setup(tmp_path, monkeypatch, still_broken={"codex"})
    hooks = repair_engine.repair_hooks(context, store, dry_run=False)
    leaks = {
        "step": "onefile_leaks",
        "title": "Leaked extraction folders",
        "status": "changed",
        "summary": "Reclaimed 25 leaked folder(s), about 40 MB. Run repair again to continue.",
        "budget_exhausted": True,
    }

    report = repair_engine.build_report([leaks, hooks], dry_run=False)
    summary = str(report["summary"])

    assert report["status"] == "partial"
    assert "No step failed. Run `hol-guard repair` again to continue the cleanup it could not finish." in summary
    assert "reaches the same answer" not in summary
    assert "These still need attention: Harness hooks." in summary
