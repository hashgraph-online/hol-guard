from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import approval_gate_nudge
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.approval_gate_nudge import APPROVAL_GATE_NUDGE, approval_gate_posture
from codex_plugin_scanner.guard.approval_gate_state import APPROVAL_GATE_STATE_FILE, ApprovalGatePublicConfig
from codex_plugin_scanner.guard.cli.render_approval_gate_nudge import print_approval_gate_nudge


def _fail_public_config(guard_home: Path) -> object:
    raise AssertionError(f"unexpected gate lookup for {guard_home}")


def test_posture_nudges_without_resident_lookup_when_gate_never_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(approval_gate_nudge, "public_config", _fail_public_config)

    posture = approval_gate_posture(tmp_path)

    assert posture["status"] == "not_set"
    assert posture["nudge"] == APPROVAL_GATE_NUDGE
    assert "Settings > Approval gate" in str(posture["setup"])


@pytest.mark.parametrize(("enabled", "status"), [(True, "protected"), (False, "not_set")])
def test_posture_follows_gate_enabled_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool, status: str
) -> None:
    _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text("{}", encoding="utf-8")
    config = ApprovalGatePublicConfig(
        enabled=enabled,
        configured=enabled,
        cooldown_seconds=0,
        cooldown_active=False,
        cooldown_expires_at=None,
        locked_until=None,
        fail_closed=False,
        strict_all_decisions=False,
        totp_enabled=False,
        totp_pending=False,
    )

    def _config(guard_home: Path) -> ApprovalGatePublicConfig:
        assert guard_home == tmp_path
        return config

    monkeypatch.setattr(approval_gate_nudge, "public_config", _config)

    assert approval_gate_posture(tmp_path)["status"] == status


def test_posture_reports_unknown_when_resident_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text("{}", encoding="utf-8")

    def _unavailable(guard_home: Path) -> object:
        raise ApprovalGateError("native_approval_gate_unavailable", f"down: {guard_home}", status=503)

    monkeypatch.setattr(approval_gate_nudge, "public_config", _unavailable)

    assert approval_gate_posture(tmp_path) == {"status": "unknown"}


def test_render_prints_nudge_only_when_gate_not_set() -> None:
    console = Console(record=True, width=200)
    print_approval_gate_nudge(console, {"approval_gate": approval_gate_posture(Path("/nonexistent-guard-home"))})
    print_approval_gate_nudge(console, {"approval_gate": {"status": "protected"}})
    print_approval_gate_nudge(console, {"approval_gate": {"status": "unknown"}})

    text = console.export_text()

    assert text.count(APPROVAL_GATE_NUDGE) == 1
    assert "Settings > Approval gate" in text


def test_guard_status_surfaces_nudge_in_json_and_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = ["guard", "status", "--home", str(tmp_path / "home"), "--guard-home", str(tmp_path / "guard-home")]
    args += ["--workspace", str(tmp_path / "workspace")]

    assert main([*args, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["approval_gate"]["status"] == "not_set"
    assert payload["approval_gate"]["nudge"] == APPROVAL_GATE_NUDGE

    assert main(args) == 0
    assert "only you can approve blocked actions" in " ".join(capsys.readouterr().out.split())


def test_guard_doctor_surfaces_nudge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["guard", "doctor", "--home", str(tmp_path / "home"), "--guard-home", str(tmp_path / "gh"), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["approval_gate"]["status"] == "not_set"
