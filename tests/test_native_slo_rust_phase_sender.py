"""Failure evidence for the owned diagnostic sender fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import native_slo_rust_phase_test_support as sender_support


@pytest.mark.parametrize("stderr_case", ["complete", "oversize"])
def test_owned_sender_failure_preserves_bounded_original_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stderr_case: str
) -> None:
    stderr_bytes = b"owned-sender-failure" if stderr_case == "complete" else b"x" * 4097
    script = (
        "import sys\n"
        "print('ready', flush=True)\n"
        f"sys.stderr.buffer.write({stderr_bytes!r})\n"
        "sys.stderr.buffer.flush()\n"
        "raise SystemExit(7)\n"
    )
    monkeypatch.setattr(sender_support, "SENDER", script)
    with pytest.raises(AssertionError, match="stderr") as failure:  # noqa: SIM117
        with sender_support.sender(tmp_path, tmp_path / "unused-endpoint") as process:
            sender_support.line(process, b"sent\n")
    assert process.returncode == 7
    detail = failure.value.args[0]
    assert detail["expected"] == b"sent\n"
    assert detail["received"] == b""
    observed = detail["stderr"]
    assert observed["data"] == stderr_bytes
    assert observed["byte_limit"] == 4096
    assert observed["capture_byte_limit"] == 4097
    assert observed["limit_exceeded"] is (len(stderr_bytes) > 4096)
    assert observed["complete"] is (len(stderr_bytes) <= 4096)
    assert observed["unavailable"] is False
    assert observed["read_error"] is None
