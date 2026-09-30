"""A proven read location must not widen workspace execution authority."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime._shell_execution_context_support import SHELL_CWD_WORKSPACE_ESCAPE
from codex_plugin_scanner.guard.runtime.shell_execution_context import model_shell_execution_context
from codex_plugin_scanner.guard.runtime.shell_secret_reads import assess_shell_reads


def _outside_workspace(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    workspace = home / "project"
    outside = tmp_path / "outside"
    workspace.mkdir(parents=True)
    outside.mkdir()
    return home, workspace, outside


def test_literal_external_read_has_location_evidence_not_execution_authority(tmp_path: Path) -> None:
    home, workspace, outside = _outside_workspace(tmp_path)
    command = f"cd {shlex.quote(str(outside))} && cat notes.txt"

    assessment = assess_shell_reads(command, cwd=workspace, home_dir=home)
    assert assessment.requires_review is False
    assert assessment.script_sources == ()
    execution = model_shell_execution_context(command, cwd=workspace, workspace_root=workspace, home_dir=home)
    assert execution.complete is False
    assert execution.reason_code == SHELL_CWD_WORKSPACE_ESCAPE


@pytest.mark.parametrize("reader", ("cat .env", "read value < .env", "python3 -c 'open(\".env\").read()'"))
def test_protected_reads_after_external_literal_cd_keep_floor(tmp_path: Path, reader: str) -> None:
    home, workspace, outside = _outside_workspace(tmp_path)
    (outside / ".env").write_text("SYNTHETIC=fixture\n", encoding="utf-8")
    assessment = assess_shell_reads(f"cd {shlex.quote(str(outside))} && {reader}", cwd=workspace, home_dir=home)
    assert assessment.requires_review is True
    assert str(outside / ".env") in assessment.sensitive_paths


def test_external_alias_to_credentials_is_not_a_benign_read(tmp_path: Path) -> None:
    home, workspace, outside = _outside_workspace(tmp_path)
    secret = outside / ".env"
    secret.write_text("SYNTHETIC=fixture\n", encoding="utf-8")
    try:
        (outside / "notes.txt").symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    assessment = assess_shell_reads(f"cd {shlex.quote(str(outside))} && cat notes.txt", cwd=workspace, home_dir=home)
    assert assessment.requires_review is True
    assert str(secret) in assessment.sensitive_paths


@pytest.mark.parametrize("launcher", ("bash check.sh", "python3 check.py", "./check"))
def test_external_mutable_code_keeps_review_without_reading_its_source(tmp_path: Path, launcher: str) -> None:
    home, workspace, outside = _outside_workspace(tmp_path)
    for name in ("check.sh", "check.py", "check"):
        (outside / name).write_text("print('synthetic')\n", encoding="utf-8")
    assessment = assess_shell_reads(f"cd {shlex.quote(str(outside))} && {launcher}", cwd=workspace, home_dir=home)
    assert assessment.requires_review is True
    assert assessment.script_requested is True
    assert assessment.incomplete is True
    assert assessment.script_sources == ()


def test_external_cwd_evidence_does_not_resolve_dynamic_directory_changes(tmp_path: Path) -> None:
    home, workspace, outside = _outside_workspace(tmp_path)
    assessment = assess_shell_reads(
        f'cd {shlex.quote(str(outside))} && cd "$UNKNOWN" && cat notes.txt', cwd=workspace, home_dir=home
    )
    assert assessment.requires_review is True
    assert assessment.incomplete is True
