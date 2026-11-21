from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

import pytest
from rich.console import Console

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import approval_gate as approval_gate_module
from codex_plugin_scanner.guard import approval_gate_nudge, native_approval_gate
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.approval_gate_nudge import APPROVAL_GATE_NUDGE, approval_gate_posture
from codex_plugin_scanner.guard.approval_gate_state import APPROVAL_GATE_STATE_FILE, ApprovalGatePublicConfig
from codex_plugin_scanner.guard.cli import commands_dispatch_admin as dispatch_admin
from codex_plugin_scanner.guard.cli.render_approval_gate_nudge import print_approval_gate_nudge
from codex_plugin_scanner.guard.desktop_notifications import DesktopNotificationSetupResult


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


def _doctor_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, *, as_json: bool) -> str:
    args = argparse.Namespace(
        notifications=mode == "notifications",
        harnesses=mode == "harnesses",
        force_notification_settings=False,
        harness=None,
        json=as_json,
    )
    rc = dispatch_admin._run_guard_doctor_command(
        args, guard_home=tmp_path, context=cast(Any, object()), store=cast(Any, object()), config=cast(Any, object())
    )
    assert rc == 0
    return capsys.readouterr().out


@pytest.mark.parametrize("mode", ["notifications", "harnesses"])
def test_guard_doctor_modes_surface_nudge_in_json_and_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    monkeypatch.setattr(dispatch_admin, "desktop_notification_setup_supported", lambda: False)
    monkeypatch.setattr(
        dispatch_admin,
        "ensure_desktop_notification_setup",
        lambda _guard_home, *, approval_url, force=False: DesktopNotificationSetupResult(
            platform="Linux",
            supported=False,
            preview_sent=False,
            settings_opened=False,
            settings_url=None,
            already_prompted=False,
            notifier_path=None,
        ),
    )

    payload = json.loads(_doctor_mode(tmp_path, capsys, mode, as_json=True))
    assert payload["approval_gate"]["status"] == "not_set"
    assert payload["approval_gate"]["nudge"] == APPROVAL_GATE_NUDGE

    text = " ".join(_doctor_mode(tmp_path, capsys, mode, as_json=False).split())
    assert "only you can approve blocked actions" in text
    assert "Settings > Approval gate" in text


def _forbid_native_gate_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("doctor must not ask the native resident for the approval gate")

    monkeypatch.setattr(approval_gate_nudge, "public_config", _forbidden)
    monkeypatch.setattr(approval_gate_module, "_approval_gate_native", _forbidden)
    monkeypatch.setattr(native_approval_gate, "native_runtime_status", _forbidden)
    monkeypatch.setattr(native_approval_gate, "native_record_resident_failure", _forbidden)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ('{"enabled": true, "totp_enabled": true}', {"status": "protected", "totp_enabled": True}),
        ('{"enabled": false, "fail_closed": true}', {"status": "protected", "totp_enabled": False}),
        ('{"enabled": false, "totp_enabled": true}', {"status": "not_set"}),
        ("{}", {"status": "not_set"}),
        ("not json", {"status": "unknown"}),
        ("[true]", {"status": "unknown"}),
        (None, {"status": "not_set"}),
    ],
)
def test_passive_posture_reads_state_file_without_native_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str | None, expected: dict[str, object]
) -> None:
    _forbid_native_gate_probe(monkeypatch)
    if state is not None:
        _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text(state, encoding="utf-8")

    posture = approval_gate_posture(tmp_path, passive=True)

    assert {key: posture[key] for key in expected} == expected
    assert ("nudge" in posture) == (expected["status"] == "not_set")


def _nested_state(depth: int) -> str:
    """An enabled-false state object whose containers nest ``depth`` levels deep."""

    return '{"enabled": false, "pad": ' + "[" * (depth - 1) + "]" * (depth - 1) + "}"


@pytest.mark.parametrize(
    "state",
    [
        '{"enabled": false, "cooldown_seconds": NaN}',
        '{"enabled": false, "cooldown_seconds": Infinity}',
        '{"enabled": false, "cooldown_seconds": -Infinity}',
        '{"enabled": false, "label": "\\ud800"}',
        '{"enabled": false, "label": "\\ud800", "label": "ok"}',
        _nested_state(128),
        _nested_state(128)[:-1] + ', "pad": 1}',
        _nested_state(100_000),
    ],
)
def test_passive_posture_reports_unknown_for_json_the_resident_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    # The resident fails closed on these, so reporting `not_set` would understate enforcement.
    _forbid_native_gate_probe(monkeypatch)
    _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text(state, encoding="utf-8")

    assert approval_gate_posture(tmp_path, passive=True) == {"status": "unknown"}


@pytest.mark.parametrize(
    "state",
    [
        _nested_state(127),
        '{"enabled": false, "cooldown_seconds": 1e400}',
        # A repeated key keeps its last value, as serde_json does.
        '{"enabled": true, "enabled": false}',
    ],
)
def test_passive_posture_accepts_json_the_resident_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    _forbid_native_gate_probe(monkeypatch)
    _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text(state, encoding="utf-8")

    assert approval_gate_posture(tmp_path, passive=True)["status"] == "not_set"


def test_passive_posture_reads_the_last_value_of_a_repeated_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_native_gate_probe(monkeypatch)
    _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text('{"enabled": false, "enabled": true}', encoding="utf-8")

    assert approval_gate_posture(tmp_path, passive=True)["status"] == "protected"


def test_doctor_modes_read_gate_posture_without_native_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _forbid_native_gate_probe(monkeypatch)
    _ = (tmp_path / APPROVAL_GATE_STATE_FILE).write_text('{"enabled": true}', encoding="utf-8")

    payload = json.loads(_doctor_mode(tmp_path, capsys, "harnesses", as_json=True))

    assert payload["approval_gate"] == {"status": "protected", "totp_enabled": False}


def test_guard_doctor_reads_gate_posture_without_native_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    guard_home = tmp_path / "gh"
    guard_home.mkdir()
    _ = (guard_home / APPROVAL_GATE_STATE_FILE).write_text('{"enabled": true}', encoding="utf-8")
    _forbid_native_gate_probe(monkeypatch)

    rc = main(["guard", "doctor", "--home", str(tmp_path / "home"), "--guard-home", str(guard_home), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["approval_gate"] == {"status": "protected", "totp_enabled": False}
    assert payload["native_runtime"]["availability"]["reason_code"] == "native_status_probe_skipped"
