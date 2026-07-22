"""Protect workspace recovery and display contracts."""

from __future__ import annotations

from pathlib import Path

_ASSET = Path(__file__).parents[1] / "src/codex_plugin_scanner/guard/daemon/static/assets/chunks/fleet-workspace.js"
_AUTHORITATIVE_SOURCE = Path(__file__).parents[1] / "dashboard/src/fleet-workspace.tsx"
_RECOVERY_SOURCE = Path(__file__).parents[1] / "dashboard/src/fleet-protection-recovery.tsx"


def _source() -> str:
    return _ASSET.read_text(encoding="utf-8")


def _authoritative_source() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in (_AUTHORITATIVE_SOURCE, _RECOVERY_SOURCE))


def test_degraded_protection_exposes_recovery_actions() -> None:
    source = _source()
    authoritative_source = _authoritative_source()

    assert "Restore full protection" in source
    assert "protection-recovery" in source
    assert "View repair details" in source
    assert "Needs repair" in source
    assert "Repair protection" in source
    assert "Repair failed checks" not in source
    assert "Open diagnostics" not in source
    assert "Guard could not confirm integrity protection yet." not in source
    assert 'hookCheck?.status === "fail"' in source
    assert 'check.check_id === "harness_hooks" && check.status === "fail"' in source
    assert "Restore full protection" in authoritative_source


def test_protection_repair_requires_local_auth_token() -> None:
    from codex_plugin_scanner.guard.daemon import server as daemon_server

    assert daemon_server._GuardDaemonHandler._requires_header_token(
        "/v1/protection/repair",
        ["v1", "protection", "repair"],
    )


def test_protect_metrics_use_locale_grouping() -> None:
    source = _source()

    assert "formatCount(props.runtime.pending_count)" in source
    assert "formatCount(props.runtime.receipt_count)" in source
    assert "formatCount(activeInstalls.length" in source
