"""Protect workspace recovery and display contracts."""

from __future__ import annotations

from pathlib import Path

_ASSET = Path(__file__).parents[1] / "src/codex_plugin_scanner/guard/daemon/static/assets/chunks/fleet-workspace.js"


def _source() -> str:
    return _ASSET.read_text(encoding="utf-8")


def test_degraded_protection_exposes_recovery_actions() -> None:
    source = _source()

    assert "Protection needs attention" in source
    assert "Repair ${harnessDisplayName(repairHarness)}" in source
    assert "href: `/apps/${repairHarness}?tab=settings`" in source
    assert 'href: "/evidence?view=commands"' in source
    assert "Open command diagnostics" in source
    assert 'hookCheck?.status === "fail"' in source
    assert 'hookCheck?.status === "unknown"' in source
    assert 'check.check_id === "harness_hooks" && check.status === "fail"' in source


def test_protect_metrics_use_locale_grouping() -> None:
    source = _source()

    assert "formatCount(props.runtime.pending_count)" in source
    assert "formatCount(props.runtime.receipt_count)" in source
    assert "formatCount(activeInstalls.length" in source
