"""Doctor separates passive setup checks from proof of Guard evaluation."""

from __future__ import annotations

import json
import subprocess
from io import StringIO

import pytest
from rich.console import Console

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import list_adapters
from codex_plugin_scanner.guard.adapters.base import _run_command_probe
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli.doctor_readiness import doctor_runtime_readiness
from codex_plugin_scanner.guard.cli.render import _render_doctor, emit_guard_payload


@pytest.mark.parametrize(
    ("setup_status", "probe", "state", "reason"),
    [
        ("active", None, "unknown", "hook_evaluation_unverified"),
        ("active", {"ok": True, "return_code": 0}, "unknown", "hook_evaluation_unverified"),
        ("active", {"ok": False, "return_code": 1}, "unknown", "harness_probe_failed"),
        ("active", {"ok": False, "timed_out": True}, "unknown", "harness_probe_timed_out"),
        ("broken", {"ok": True}, "fail", "guard_setup_broken"),
        ("partial", {"ok": True}, "unknown", "hook_registration_unconfirmed"),
        ("not_found", None, "unknown", "hook_registration_unconfirmed"),
        ("active", {"skipped": True, "ok": None}, "unknown", "harness_probe_not_run"),
    ],
)
def test_doctor_json_does_not_promote_registration_or_cli_success_to_readiness(
    tmp_path, monkeypatch, capsys, setup_status, probe, state, reason
) -> None:
    monkeypatch.setattr(
        CodexHarnessAdapter,
        "diagnostics",
        lambda _self, _context: {
            "harness": "codex",
            "installed": True,
            "command_available": True,
            "setup_status": setup_status,
            "runtime_probe": probe,
            "native_hook_state": {"integrity_status": "valid", "protection_active": True},
            "warnings": [],
            "artifacts": [],
        },
    )
    rc = main(
        [
            "guard",
            "doctor",
            "codex",
            "--json",
            "--home",
            str(tmp_path / "home"),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--workspace",
            str(tmp_path / "workspace"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["setup_status"] == setup_status
    assert payload["runtime_readiness"]["state"] == state
    assert payload["runtime_readiness"]["reason_code"] == reason


def test_global_doctor_reports_readiness_for_every_registered_harness(tmp_path, capsys) -> None:
    rc = main(
        [
            "guard",
            "doctor",
            "--json",
            "--home",
            str(tmp_path / "home"),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--workspace",
            str(tmp_path / "workspace"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert {item["harness"] for item in payload["adapters"]} == {item.harness for item in list_adapters()}
    assert all(item["runtime_readiness"]["state"] == "unknown" for item in payload["adapters"])


@pytest.mark.parametrize("probe", [None, {"ok": True, "return_code": 0}])
def test_doctor_text_shows_unverified_evaluation_even_when_setup_is_active(capsys, probe) -> None:
    emit_guard_payload(
        "doctor",
        {
            "harness": "codex",
            "installed": True,
            "command_available": True,
            "setup_status": "active",
            "runtime_probe": probe,
            "warnings": [],
        },
        False,
    )
    output = " ".join(capsys.readouterr().out.split())

    assert "Registration" in output
    assert "Runtime readiness" in output
    assert "Unverified" in output
    assert "authenticated Guard decision" in output


def test_global_doctor_text_does_not_label_detected_harness_ready(capsys) -> None:
    emit_guard_payload(
        "doctor",
        {
            "tables": [],
            "adapters": [{"harness": "codex", "installed": True, "command_available": True}],
        },
        False,
    )
    output = " ".join(capsys.readouterr().out.split())

    assert "Registration" in output
    assert "Runtime readiness" in output
    assert "Unverified" in output
    assert "No Guard decision verified" in output
    assert "Ready" not in output


@pytest.mark.parametrize("installed", [True, False])
@pytest.mark.parametrize("width", [80, 120])
def test_global_doctor_distinguishes_detection_from_missing_registration(installed, width) -> None:
    stream = StringIO()
    console = Console(file=stream, width=width, color_system=None)
    _render_doctor(
        console,
        {
            "tables": [],
            "adapters": [{"harness": "codex", "installed": installed, "setup_status": "not_found"}],
        },
    )
    output = " ".join(stream.getvalue().split())

    assert "Detection" in output
    detection = "Found" if installed else "Not found"
    assert f"codex {detection} Not found Unverified" in output


def test_doctor_readiness_does_not_echo_raw_probe_data_or_accept_claimed_health() -> None:
    readiness = doctor_runtime_readiness(
        {
            "setup_status": "active",
            "runtime_probe": {
                "ok": True,
                "ready": True,
                "authenticated": True,
                "stdout": "private-probe-output",
                "stderr": "private-probe-error",
            },
            "runtime_readiness": {"state": "pass"},
            "trust": {"healthy": True},
        }
    )

    assert readiness["state"] == "unknown"
    assert readiness["reason_code"] == "hook_evaluation_unverified"
    assert "private-probe" not in json.dumps(readiness)


@pytest.mark.parametrize("width", [48, 80, 120])
def test_doctor_readiness_is_visible_at_narrow_terminal_widths(width) -> None:
    stream = StringIO()
    console = Console(file=stream, width=width, color_system=None)
    _render_doctor(
        console,
        {
            "harness": "antigravity",
            "installed": True,
            "command_available": True,
            "setup_status": "active",
            "warnings": [],
        },
    )

    output = stream.getvalue()
    assert "Unverified" in output
    assert "Registration" in output
    assert "active" in output


@pytest.mark.parametrize("key", ["command", "paths", "config"])
@pytest.mark.parametrize("timed_out", [False, True])
def test_doctor_identifies_known_nested_probe_failures(key, timed_out) -> None:
    readiness = doctor_runtime_readiness(
        {"setup_status": "active", "runtime_probe": {key: {"ok": False, "timed_out": timed_out}}}
    )

    assert readiness["state"] == "unknown"
    assert readiness["reason_code"] == ("harness_probe_timed_out" if timed_out else "harness_probe_failed")


def test_global_doctor_validates_registration_without_executable_probes(tmp_path, monkeypatch, capsys) -> None:
    def unexpected_subprocess(*_args, **_kwargs):
        pytest.fail("Global doctor must not run harness CLI probes")

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.base.subprocess.run", unexpected_subprocess)
    for adapter in ("hermes", "openclaw", "opencode"):
        monkeypatch.setattr(f"codex_plugin_scanner.guard.adapters.{adapter}._command_available", lambda _command: True)
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    codex_home.joinpath("config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
    entry = {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": "python -I ./codex_daemon_hook_bridge.py '{}'",
                "statusMessage": "HOL Guard checking tool action",
            }
        ],
    }
    codex_home.joinpath("hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    event: [entry] for event in ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.codex._command_available", lambda _command: True)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.codex._verify_live_hook_manifest",
        lambda _context, **_kwargs: {
            "event_matches": {"PreToolUse": False, "PermissionRequest": False},
            "integrity_status": "tampered",
            "integrity_reason": "codex_hook_interpreter_path_mismatch",
        },
    )
    rc = main(
        [
            "guard",
            "doctor",
            "--json",
            "--home",
            str(home),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--workspace",
            str(tmp_path / "workspace"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    codex = next(item for item in payload["adapters"] if item["harness"] == "codex")

    assert rc == 0
    assert codex["setup_status"] == "broken"
    assert codex["runtime_readiness"]["state"] == "fail"
    assert codex["runtime_readiness"]["reason_code"] == "guard_setup_broken"


def test_passive_probe_scope_resets_after_nested_scope_and_exception(monkeypatch) -> None:
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, returncode=0, stdout="probe", stderr="")

    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.base.subprocess.run", run)
    with pytest.raises(ValueError, match="fixture failure"), without_command_probes():
        with without_command_probes():
            skipped = _run_command_probe(["fixture-cli", "--help"])
            assert skipped["skipped"] is True
            assert skipped["ok"] is None
        assert _run_command_probe(["fixture-cli", "--help"])["skipped"] is True
        raise ValueError("fixture failure")

    assert calls == []
    assert _run_command_probe(["fixture-cli", "--help"])["ok"] is True
    assert calls == [["fixture-cli", "--help"]]


def test_global_doctor_text_distinguishes_partial_registration_and_probe_failures(capsys) -> None:
    emit_guard_payload(
        "doctor",
        {
            "tables": [],
            "adapters": [
                {"harness": "hermes", "setup_status": "partial"},
                {
                    "harness": "opencode",
                    "setup_status": "active",
                    "runtime_readiness": {
                        "state": "unknown",
                        "reason_code": "harness_probe_failed",
                        "detail": "raw-projection-marker",
                    },
                },
                {
                    "harness": "codex",
                    "setup_status": "broken",
                    "runtime_readiness": {
                        "state": "unknown",
                        "reason_code": "harness_probe_not_run",
                    },
                },
            ],
        },
        False,
    )
    output = " ".join(capsys.readouterr().out.split())

    assert "Partial" in output
    assert "CLI check failed" in output
    assert "raw-projection-marker" not in output
    assert "Setup broken" in output
