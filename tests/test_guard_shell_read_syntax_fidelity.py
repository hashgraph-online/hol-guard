"""Source inspection must preserve shell syntax without executing input."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.shell_execution_context import model_shell_execution_context


def test_noclobber_redirection_is_not_a_pipeline(tmp_path: Path) -> None:
    context = model_shell_execution_context("ls missing 2>|/dev/null | head -40", cwd=tmp_path)
    assert len(context.segments) == 2
    assert context.segments[0].tokens == ("ls", "missing", "2>|/dev/null")
    assert context.segments[1].tokens == ("head", "-40")


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
