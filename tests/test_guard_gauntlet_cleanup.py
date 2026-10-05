"""Cleanup failures must not skip independent containment or leak diagnostics."""

from pathlib import Path

import pytest

from ci.gauntlet import cleanup as lifecycle


@pytest.mark.parametrize("failed_steps", [(), ("daemon",), ("native",), ("daemon", "native")])
def test_cleanup_attempts_both_steps_and_keeps_failure_details_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed_steps: tuple[str, ...]
) -> None:
    calls: list[str] = []

    def cleanup(step: str) -> None:
        calls.append(step)
        if step in failed_steps:
            try:
                raise ValueError("private underlying failure")
            except ValueError as exc:
                raise RuntimeError("private cleanup context") from exc

    monkeypatch.setattr(lifecycle.probe, "_cleanup_installed_daemon", lambda _daemon: cleanup("daemon"))
    monkeypatch.setattr(lifecycle.probe, "_cleanup_native", lambda _identity, _home: cleanup("native"))

    result = lifecycle.cleanup_case_resources(object(), object(), tmp_path / "guard-home", tmp_path)

    assert calls == ["daemon", "native"]
    if failed_steps:
        assert result == {"cleanup_ok": False, "cleanup_error": "RuntimeError"}
        diagnostic = (tmp_path / "cleanup-error.txt").read_text()
        assert "private underlying failure" in diagnostic
        assert "private cleanup context" in diagnostic
        assert "private" not in str(result)
        for step in failed_steps:
            assert ("installed-daemon" if step == "daemon" else "native-resident") in diagnostic
    else:
        assert result == {"cleanup_ok": True}
        assert not (tmp_path / "cleanup-error.txt").exists()


@pytest.mark.parametrize("write_error", [PermissionError("private path"), OSError("disk full")])
def test_diagnostic_write_failure_preserves_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, write_error: OSError
) -> None:
    calls: list[str] = []

    def failed_daemon(_daemon: object) -> None:
        calls.append("daemon")
        raise RuntimeError("private cleanup failure")

    def failed_write(*args: object, **kwargs: object) -> None:
        raise write_error

    monkeypatch.setattr(lifecycle.probe, "_cleanup_installed_daemon", failed_daemon)
    monkeypatch.setattr(lifecycle.probe, "_cleanup_native", lambda *_args: calls.append("native"))
    monkeypatch.setattr(Path, "write_text", failed_write)

    result = lifecycle.cleanup_case_resources(object(), object(), tmp_path / "guard-home", tmp_path)

    assert calls == ["daemon", "native"]
    assert result == {
        "cleanup_ok": False,
        "cleanup_error": "RuntimeError",
        "cleanup_diagnostic_error": type(write_error).__name__,
    }
    assert "private" not in str(result)
