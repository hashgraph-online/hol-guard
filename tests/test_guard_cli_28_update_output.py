"""Guard CLI update output behavior."""

from __future__ import annotations

from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_update_human_output_uses_notes_instead_of_stderr_for_current(self, capsys):
        emit_guard_payload(
            "update",
            {
                "current_version": "2.0.36",
                "installer": "pipx",
                "command": ["pipx", "upgrade", "hol-guard"],
                "dry_run": False,
                "resulting_version": "2.0.36",
                "status": "current",
                "message": "HOL Guard is already current.",
                "notes": ["upgrading shared libraries...", "upgrading hol-guard..."],
                "stdout": "hol-guard is already at latest version 2.0.36",
                "stderr": "upgrading shared libraries...\nupgrading hol-guard...",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard update: current" in output
        assert "HOL Guard is already current." in output
        assert "Notes" in output
        assert "upgrading shared libraries..." in output
        assert "stdout" not in output
        assert "stderr" not in output

    def test_guard_update_failed_output_keeps_stdout_details(self, capsys):
        emit_guard_payload(
            "update",
            {
                "current_version": "2.0.36",
                "installer": "pipx",
                "command": ["pipx", "upgrade", "hol-guard"],
                "dry_run": False,
                "status": "failed",
                "message": "HOL Guard update failed.",
                "stdout": "pipx could not upgrade hol-guard in the current environment",
                "stderr": "",
                "error": "",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard update: failed" in output
        assert "stdout" in output
        assert "pipx could not upgrade hol-guard in the current environment" in output

    def test_guard_update_deferred_output_keeps_propagation_detail_calm(self, capsys):
        emit_guard_payload(
            "update",
            {
                "current_version": "2.2.1",
                "installer": "pipx",
                "command": [
                    "pipx",
                    "runpip",
                    "hol-guard",
                    "install",
                    "--upgrade",
                    "--force-reinstall",
                    "hol-guard==2.2.3",
                ],
                "dry_run": False,
                "resulting_version": "2.2.1",
                "status": "deferred",
                "message": (
                    "The newest HOL Guard release is still reaching PyPI. "
                    "Your current installation remains active; try the update again shortly."
                ),
                "stderr": "ERROR: No matching distribution found for hol-guard==2.2.3",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard update: deferred" in output
        assert "current installation remains active" in output
        assert "stderr" not in output
