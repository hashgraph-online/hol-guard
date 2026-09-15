"""Focused regressions for shell-read fail-closed and false-positive boundaries."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.shell_secret_reads import assess_shell_reads


def test_path_qualified_executable_outside_guarded_roots_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    home = tmp_path / "home"
    workspace.mkdir()
    home.mkdir()
    outside = tmp_path / "check"
    outside.write_text("#!/bin/sh\ncat .env\n")
    outside.chmod(0o755)

    assessment = assess_shell_reads("../check", cwd=workspace, home_dir=home)
    assert assessment.script_requested
    assert assessment.incomplete
    assert assessment.requires_review
    assert evaluate_command("../check", cwd=workspace, home_dir=home).minimum_action == "review"


def test_failed_literal_cd_skips_the_entire_and_pipeline_branch(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = "cd missing && rg -n GuardAction src tests | head -40"

    assessment = assess_shell_reads(command, cwd=workspace, home_dir=tmp_path / "home")
    assert not assessment.sensitive_paths
    assert not assessment.script_requested
    assert not assessment.incomplete


def test_failed_literal_cd_skips_benign_test_pipeline_without_escalation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = "cd missing && npx tsc --noEmit --pretty 2>&1 | head -40"

    assessment = assess_shell_reads(command, cwd=workspace, home_dir=tmp_path / "home")
    assert not assessment.requires_review


def test_failed_literal_cd_does_not_hide_or_branch_read(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = "cd missing || cat .env"

    assessment = assess_shell_reads(command, cwd=workspace, home_dir=tmp_path / "home")
    assert assessment.requires_review
    assert assessment.incomplete


def test_failed_literal_cd_or_recovery_does_not_hide_later_and_read(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    command = "cd missing || true && cat .env"

    assessment = assess_shell_reads(command, cwd=workspace, home_dir=tmp_path / "home")
    assert assessment.requires_review
    assert assessment.incomplete
