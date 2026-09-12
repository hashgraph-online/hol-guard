"""Source inspection must preserve shell syntax without executing input."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.shell_execution_context import model_shell_execution_context
from codex_plugin_scanner.guard.runtime.shell_secret_reads import assess_shell_reads


@pytest.mark.parametrize(
    "command",
    (
        "read value < .env",
        "read value 3< .env",
        "read value <> .env",
        "cat 0<.env",
        "source .env",
        ". .env",
        "bash -cl 'cat .env'",
        "bash -lc 'cat .env'",
        "command -p cat .env",
    ),
)
def test_read_syntax_keeps_credential_operands(command: str, tmp_path: Path) -> None:
    assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert assessment.sensitive_paths == (str(tmp_path / ".env"),)
    assert assessment.requires_review


@pytest.mark.parametrize(
    "command",
    (
        "echo '< .env'",
        "printf '%s' '3< .env'",
        "command -pv cat",
        "command -Vp cat",
        "git diff HEAD -- file.py | head -20",
        "ls missing 2>|/dev/null | head -40",
    ),
)
def test_literal_text_and_stdout_filters_are_not_script_reads(command: str, tmp_path: Path) -> None:
    assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert not assessment.requires_review
    assert not assessment.sensitive_paths


def test_raw_parser_keeps_invalid_execution_prefix(tmp_path: Path) -> None:
    command = "command --unknown cat .env"
    model = parse_shell_command(command, cwd=tmp_path, normalize_wrappers=False)
    assert model.segments[0].executable == "command"
    assert model.segments[0].arguments[0] == "--unknown"
    assessment = assess_shell_reads(command, cwd=tmp_path, home_dir=tmp_path)
    assert assessment.incomplete
    assert assessment.requires_review


def test_noclobber_redirection_is_not_a_pipeline(tmp_path: Path) -> None:
    context = model_shell_execution_context("ls missing 2>|/dev/null | head -40", cwd=tmp_path)
    assert len(context.segments) == 2
    assert context.segments[0].tokens == ("ls", "missing", "2>|/dev/null")
    assert context.segments[1].tokens == ("head", "-40")


def test_scanner_follows_a_first_sourced_script_without_reading_credentials(tmp_path: Path) -> None:
    script = tmp_path / "check.sh"
    script.write_text("cat .env\n")
    assessment = assess_shell_reads("source check.sh", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.sensitive_paths == (str(tmp_path / ".env"),)
    assert assessment.script_sources
    assert not (tmp_path / ".env").exists()


def test_proven_home_inspection_preserves_original_redirection(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    (workspace / "src").mkdir(parents=True)
    command = f"cd {workspace} && grep -rn TODO src 2>/dev/null | head -20"
    assert not assess_shell_reads(command, cwd=None, home_dir=home).requires_review


def test_shell_line_continuation_stays_in_one_execution_segment(tmp_path: Path) -> None:
    command = "sed -i '' \\" + "\n  -e 's/old/new/g' \\" + "\n  src/example.ts"
    context = model_shell_execution_context(command, cwd=tmp_path)
    assert len(context.segments) == 1
    assert context.segments[0].tokens == (
        "sed",
        "-i",
        "",
        "-e",
        "s/old/new/g",
        "src/example.ts",
    )


def test_known_python_module_does_not_inherit_generic_local_module_floor(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/example.py").write_text("value = 1\n", encoding="utf-8")
    assessment = assess_shell_reads("python3 -m ruff format src/example.py", cwd=tmp_path, home_dir=tmp_path)
    assert not assessment.requires_review


def test_unknown_python_module_keeps_generic_local_module_floor(tmp_path: Path) -> None:
    assessment = assess_shell_reads("python3 -m reader", cwd=tmp_path, home_dir=tmp_path)
    assert assessment.requires_review
    assert assessment.script_requested
