"""Literal wrapper inspection does not bypass secret or mutable-code floors."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.shell_secret_reads import assess_shell_reads


@pytest.mark.parametrize("shell", ("sh", "bash", "dash", "ash", "zsh"))
def test_literal_wrapper_does_not_invent_a_script_file(shell: str, tmp_path: Path) -> None:
    assessment = assess_shell_reads(f"{shell} -lc 'git stash list'", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.requires_review is False
    assert assessment.script_sources == ()


@pytest.mark.parametrize("payload", ("cat .env", "git stash; cat .env", "git stash && cat .npmrc"))
def test_literal_wrapper_preserves_protected_reads(payload: str, tmp_path: Path) -> None:
    assessment = assess_shell_reads(f"zsh -lc '{payload}'", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.requires_review is True
    assert assessment.sensitive_paths


@pytest.mark.parametrize(
    "command",
    (
        "zsh -lc './check'",
        "bash -c 'python3 check.py'",
        "bash --rcfile custom -lc 'git stash'",
        "ksh -c 'echo harmless'",
        "bash -cl 'git stash'",
        "zsh -lc 'cat \"$INPUT\"'",
        "zsh -lc 'cat \"$1\"' ignored .env",
        "zsh -lc 'git stash' && ./check",
    ),
)
def test_ambiguous_or_mutable_wrapper_keeps_execution_review(command: str, tmp_path: Path) -> None:
    assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert assessment.requires_review is True
