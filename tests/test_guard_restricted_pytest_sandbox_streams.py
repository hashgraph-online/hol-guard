"""Standard-stream containment for the restricted pytest backend."""

import os
import sys

import pytest

from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox
from codex_plugin_scanner.guard.runtime.restricted_pytest_sandbox import _run_backend_process


def test_restricted_process_has_noninteractive_sanitized_standard_streams(
    capsys: pytest.CaptureFixture[str],
) -> None:
    return_code = _run_backend_process(
        [
            sys.executable,
            "-c",
            "import sys; print('stdin=' + repr(sys.stdin.read())); print('\\x1b[31mresult')",
        ],
        env=os.environ,
        timeout_seconds=5,
    )

    captured = capsys.readouterr()
    assert return_code == 0
    assert "stdin=''" in captured.out
    assert "\x1b" not in captured.out
    assert "result" in captured.out


def test_private_capability_stdout_is_bounded_and_not_replayed(capsys):
    output = bytearray()
    code = _run_backend_process(
        [sys.executable, "-c", "import sys; print('capability-result'); print('diagnostic', file=sys.stderr)"],
        env=os.environ,
        timeout_seconds=5,
        stdout_capture=output,
    )
    assert code == 0 and output == b"capability-result\n"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "diagnostic" in captured.err


@pytest.fixture
def _fixed_process_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests are about the replayed output, not the native process ceiling.
    monkeypatch.setattr(restricted_pytest_sandbox, "_current_user_process_ceiling", lambda: 4096)


def _emit(text: str, code: int) -> list[str]:
    return [sys.executable, "-c", f"import sys; print({text!r}, file=sys.stderr); sys.exit({code})"]


@pytest.mark.usefixtures("_fixed_process_ceiling")
def test_a_failed_run_that_reports_a_denied_write_gets_the_sandbox_note(capsys):
    code = _run_backend_process(
        _emit("Error: EPERM: operation not permitted, mkdir '/work/reports'", 1),
        env=os.environ,
        timeout_seconds=5,
        write_denial_note="Only $TMPDIR is writable.",
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.endswith("mkdir '/work/reports'\n\n[HOL Guard] Only $TMPDIR is writable.\n")
    assert "HOL Guard" not in captured.out


@pytest.mark.usefixtures("_fixed_process_ceiling")
def test_a_merged_run_puts_the_note_after_its_merged_output(capsys):
    code = _run_backend_process(
        _emit("OSError: [Errno 30] Read-only file system: 'cache'", 2),
        env=os.environ,
        timeout_seconds=5,
        merge_stderr=True,
        write_denial_note="Only $TMPDIR is writable.",
    )
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out.endswith("'cache'\n\n[HOL Guard] Only $TMPDIR is writable.\n")
    assert captured.err == ""


@pytest.mark.parametrize(
    ("text", "exit_code", "note"),
    [
        ("EPERM: operation not permitted", 0, "note"),
        ("AssertionError: expected 2, got 3", 1, "note"),
        ("EPERM: operation not permitted", 1, None),
    ],
    ids=["passing-run", "unrelated-failure", "no-note-for-this-sandbox"],
)
@pytest.mark.usefixtures("_fixed_process_ceiling")
def test_the_note_appears_only_for_a_failed_run_that_reports_a_denial(capsys, text, exit_code, note):
    code = _run_backend_process(_emit(text, exit_code), env=os.environ, timeout_seconds=5, write_denial_note=note)
    captured = capsys.readouterr()
    assert code == exit_code
    assert "HOL Guard" not in captured.err + captured.out


def test_replay_keeps_crlf_line_ends_and_fits_a_code_page_pipe() -> None:
    import io

    from codex_plugin_scanner.guard.runtime.restricted_pytest_sandbox import _replay_sandbox_output

    destination = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")
    _replay_sandbox_output(io.BytesIO(b"calc ok\r\nbar\rbaz \xe2\x9c\x93\n"), destination)
    destination.buffer.seek(0)
    assert destination.buffer.read() == b"calc ok\nbar?baz ?\n"
