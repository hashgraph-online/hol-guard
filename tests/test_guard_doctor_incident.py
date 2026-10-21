"""Offline incident output preserves authenticated versus loaded-runtime boundaries."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.cli.commands_router import run_guard_command
from codex_plugin_scanner.guard.cli.doctor_incident import codex_incident_report, run_codex_incident_export
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")


def test_incident_export_is_independent_of_guard_store(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_router.GuardStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("store opened")),
    )
    output = io.StringIO()
    args = argparse.Namespace(
        guard_command="doctor",
        harness="codex",
        incident=True,
        json=True,
        home=str(context.home_dir),
        guard_home=str(context.guard_home),
        workspace=None,
        repair=False,
    )

    assert run_guard_command(args, output_stream=output) == 0
    report = json.loads(output.getvalue())
    assert report["configured"]["config_status"] == "missing"
    assert report["loaded_harness"]["state"] == "unknown"
    assert report["authenticated_hook_decision"]["state"] == "unknown"
    assert report["daemon"]["discovery_authentication"] == "unverified"
    assert len(output.getvalue().encode()) < 8192


def test_incident_export_reports_authenticated_config_without_loaded_claim(tmp_path: Path) -> None:
    context = _context(tmp_path)
    CodexHarnessAdapter().install(context)

    report = codex_incident_report(context)

    assert report["configured"]["manifest_integrity"] == "valid"
    assert all(report["configured"]["managed_events"].values())
    assert report["configured"]["manifest_package_version"] == report["cli_package_version"]
    assert len(report["configured"]["bridge_sha256"]) == 64
    assert len(report["configured"]["interpreter_sha256"]) == 64
    assert report["configured"]["manifest_generated_at"]
    assert report["loaded_harness"]["state"] == "unknown"
    assert report["authenticated_hook_decision"]["state"] == "unknown"


def test_incident_export_rejects_oversized_config_without_reading_it(tmp_path: Path) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir()
    config_path.write_bytes(b" " * (1024 * 1024 + 1))

    report = codex_incident_report(context)

    assert report["configured"]["config_status"] == "too_large"
    assert report["configured"]["manifest_integrity"] == "unverified"
    assert report["configured"]["manifest_package_version"] is None
    assert report["configured"]["bridge_sha256"] is None


def test_incident_export_does_not_call_unreadable_hooks_missing(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    config_path = CodexHarnessAdapter._hook_config_path(context)
    config_path.parent.mkdir()
    config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    from codex_plugin_scanner.guard.cli import doctor_incident

    original_read = doctor_incident._bounded_regular_bytes
    monkeypatch.setattr(
        doctor_incident,
        "_bounded_regular_bytes",
        lambda path: (None, "unreadable") if path == hooks_path else original_read(path),
    )

    report = codex_incident_report(context)

    assert report["configured"]["hooks_status"] == "unreadable"
    assert report["configured"]["manifest_integrity"] == "unverified"
    assert report["configured"]["reason_code"] == "codex_hooks_unavailable"


def test_incident_export_reports_legacy_hooks_when_toml_config_is_missing(tmp_path: Path) -> None:
    context = _context(tmp_path)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    hooks_path.parent.mkdir()
    hooks_path.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": []}]}}), encoding="utf-8")

    report = codex_incident_report(context)

    assert report["configured"]["config_status"] == "missing"
    assert report["configured"]["hooks_status"] == "read"
    assert report["configured"]["manifest_integrity"] != "valid"
    assert report["configured"]["manifest_package_version"] is None
    assert report["loaded_harness"]["state"] == "unknown"


def test_incident_export_counts_duplicate_configured_hooks_without_exposing_commands(tmp_path: Path, capsys) -> None:
    context = _context(tmp_path)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    hooks_path.parent.mkdir()
    hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": ".*", "hooks": [{"type": "command", "command": "private-pipx-command"}]},
                        {"matcher": ".*", "hooks": [{"type": "command", "command": "private-uv-command"}]},
                    ],
                    "PermissionRequest": "malformed-groups",
                }
            }
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "guard",
            "doctor",
            "codex",
            "--incident",
            "--json",
            "--home",
            str(context.home_dir),
            "--guard-home",
            str(context.guard_home),
        ]
    )
    output = capsys.readouterr()
    assert result == 0
    assert output.err == ""
    report = json.loads(output.out)

    assert report["configured"]["event_group_counts"]["PreToolUse"] == 2
    assert report["configured"]["event_handler_counts"]["PreToolUse"] == 2
    assert report["configured"]["event_group_counts"]["PermissionRequest"] is None
    assert report["configured"]["event_handler_counts"]["PermissionRequest"] is None
    assert report["configured"]["event_group_counts"]["UserPromptSubmit"] == 0
    assert report["configured"]["manifest_integrity"] != "valid"
    assert report["loaded_harness"]["state"] == "unknown"
    assert "private-pipx-command" not in output.out
    assert "private-uv-command" not in output.out
    assert len(output.out.encode()) < 8192


def test_incident_export_does_not_count_malformed_group_or_handler_entries(tmp_path: Path) -> None:
    context = _context(tmp_path)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    hooks_path.parent.mkdir()
    hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [None],
                    "PermissionRequest": [{"hooks": [None]}],
                    "UserPromptSubmit": [{"hooks": [{}]}],
                }
            }
        ),
        encoding="utf-8",
    )

    configured = codex_incident_report(context)["configured"]

    assert configured["event_group_counts"]["PreToolUse"] is None
    assert configured["event_handler_counts"]["PreToolUse"] is None
    assert configured["event_group_counts"]["PermissionRequest"] == 1
    assert configured["event_handler_counts"]["PermissionRequest"] is None
    assert configured["event_group_counts"]["UserPromptSubmit"] == 1
    assert configured["event_handler_counts"]["UserPromptSubmit"] == 1


def test_incident_export_marks_hook_integer_conversion_error_malformed(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    hooks_path.parent.mkdir()
    hooks_path.write_text('{"hooks":{"PreToolUse":[]}}', encoding="utf-8")
    from codex_plugin_scanner.guard.cli import doctor_incident

    original_loads = doctor_incident.json.loads

    def fail_hook_parse(value: str | bytes):
        if value == b'{"hooks":{"PreToolUse":[]}}':
            raise ValueError("private integer conversion detail")
        return original_loads(value)

    monkeypatch.setattr(doctor_incident.json, "loads", fail_hook_parse)

    report = codex_incident_report(context)

    assert report["configured"]["hooks_status"] == "malformed"
    assert report["configured"]["manifest_integrity"] == "unverified"
    assert "private integer conversion detail" not in json.dumps(report)


def test_incident_cli_reports_selected_workspace_hooks_without_authenticating_them(tmp_path: Path, capsys) -> None:
    context = _context(tmp_path)
    workspace = tmp_path / "workspace"
    project_context = HarnessContext(home_dir=context.home_dir, workspace_dir=workspace, guard_home=context.guard_home)
    project_config = CodexHarnessAdapter._config_hook_pairs(project_context)[1][0]
    project_config.parent.mkdir(parents=True)
    project_config.write_text('[hooks]\nPreToolUse = [{ matcher = ".*", hooks = [] }]\n', encoding="utf-8")

    result = main(
        [
            "guard",
            "doctor",
            "codex",
            "--incident",
            "--json",
            "--home",
            str(context.home_dir),
            "--guard-home",
            str(context.guard_home),
            "--workspace",
            str(workspace),
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["workspace"]["selected"] is True
    assert report["workspace"]["event_group_counts"]["PreToolUse"] == 1
    assert report["workspace"]["authentication"] == "unverified_local_configuration"
    assert report["configured"]["manifest_package_version"] is None
    assert report["loaded_harness"]["state"] == "unknown"


def test_incident_export_does_not_expose_identity_from_tampered_manifest(tmp_path: Path) -> None:
    context = _context(tmp_path)
    CodexHarnessAdapter().install(context)
    manifest_path = hook_manifest_path(context.guard_home, CodexHarnessAdapter._hook_config_path(context))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["package_version"] = "forged-version"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = codex_incident_report(context)

    assert report["configured"]["manifest_integrity"] != "valid"
    assert report["configured"]["manifest_package_version"] is None
    assert report["configured"]["bridge_sha256"] is None
    assert report["loaded_harness"]["state"] == "unknown"


def test_incident_cli_parser_emits_one_bounded_json_report(tmp_path: Path, capsys) -> None:
    context = _context(tmp_path)

    result = main(
        [
            "guard",
            "doctor",
            "codex",
            "--incident",
            "--json",
            "--home",
            str(context.home_dir),
            "--guard-home",
            str(context.guard_home),
        ]
    )

    output = capsys.readouterr()
    assert result == 0
    assert output.err == ""
    assert json.loads(output.out)["schema"] == "hol-guard.codex-incident.v1"
    assert len(output.out.encode()) < 8192


def test_incident_cli_expands_home_shorthand(tmp_path: Path, capsys, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setenv("HOME", str(context.home_dir))
    monkeypatch.setenv("USERPROFILE", str(context.home_dir))
    config_path = CodexHarnessAdapter._hook_config_path(context)
    config_path.parent.mkdir()
    config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")

    result = main(
        [
            "guard",
            "doctor",
            "codex",
            "--incident",
            "--json",
            "--home",
            "~",
            "--guard-home",
            str(context.guard_home),
        ]
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out)["configured"]["config_status"] == "read"


def test_incident_export_never_echoes_untrusted_config_or_exception(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir()
    config_path.write_text("[features]\nhooks = true\n# PRIVATE_TOKEN\n", encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.doctor_incident.verify_live_hook_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE_TOKEN")),
    )

    report = codex_incident_report(context)

    assert report["configured"]["reason_code"] == "codex_integrity_probe_failed"
    assert report["configured"]["integrity_probe_exception_class"] == "RuntimeError"
    assert "PRIVATE_TOKEN" not in json.dumps(report)


def test_incident_export_keeps_json_when_journal_path_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.doctor_incident.load_bounded_incident_lifecycle_events",
        lambda _guard_home: (_ for _ in ()).throw(OSError("private incident detail")),
    )

    report = codex_incident_report(context)

    assert report["timeline"]["status"] == "journal_unavailable"
    assert report["timeline"]["events"] == []
    assert "private incident detail" not in json.dumps(report)


def test_incident_export_keeps_json_when_daemon_discovery_is_unreadable(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.doctor_incident.load_authenticated_daemon_state",
        lambda _guard_home: (_ for _ in ()).throw(OSError("private discovery detail")),
    )

    report = codex_incident_report(context)

    assert report["daemon"]["discovery_authentication"] == "unverified"
    assert "private discovery detail" not in json.dumps(report)


def test_incident_export_rejects_repair_without_running_diagnostics(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.doctor_incident.codex_incident_report",
        lambda _context: (_ for _ in ()).throw(AssertionError("diagnostics ran")),
    )
    output = io.StringIO()

    result = run_codex_incident_export(argparse.Namespace(harness="codex", repair=True), context, output_stream=output)

    assert result == 2
    assert json.loads(output.getvalue())["error"] == "incident_export_requires_codex_without_other_doctor_actions"
