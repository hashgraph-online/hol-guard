import os
from pathlib import Path

import pytest

from codex_plugin_scanner.action_runner import _write_outputs
from codex_plugin_scanner.safe_output import write_text_atomic_no_follow


def test_no_follow_inverse_removal_preserves_symlinked_parent_target(tmp_path: Path):
    from codex_plugin_scanner.safe_output import remove_file_no_follow

    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "user-file"
    target.write_bytes(b"preserve")
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        remove_file_no_follow(linked / "user-file")
    assert target.read_bytes() == b"preserve"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode restoration")
def test_no_follow_output_restores_declared_mode_and_removal_is_idempotent(tmp_path: Path):
    from codex_plugin_scanner.safe_output import remove_file_no_follow, write_bytes_atomic_no_follow

    target = tmp_path / "owned-file"
    write_bytes_atomic_no_follow(target, b"inverse", mode=0o640)
    assert target.read_bytes() == b"inverse"
    assert target.stat().st_mode & 0o777 == 0o640
    remove_file_no_follow(target)
    remove_file_no_follow(target)
    assert not target.exists()


def test_atomic_output_replaces_symlink_without_overwriting_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    output = tmp_path / "report.json"
    output.symlink_to(outside)

    write_text_atomic_no_follow(output, "safe")

    assert outside.read_text(encoding="utf-8") == "preserve"
    assert output.is_symlink() is False
    assert output.read_text(encoding="utf-8") == "safe"


def test_atomic_output_rejects_absolute_symlinked_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)

    try:
        write_text_atomic_no_follow(linked_parent / "report.json", "unsafe")
    except OSError as error:
        assert "symlinked output directory" in str(error)
    else:
        raise AssertionError("absolute symlinked output parent was accepted")

    assert not (outside / "report.json").exists()


def test_atomic_output_creates_missing_parents_without_path_based_mkdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "missing" / "nested" / "report.json"

    def reject_path_mkdir(*_args, **_kwargs):
        raise AssertionError("path-based mkdir used")

    monkeypatch.setattr(Path, "mkdir", reject_path_mkdir)
    write_text_atomic_no_follow(output, "safe")

    assert output.read_text(encoding="utf-8") == "safe"


def test_github_outputs_use_multiline_protocol_for_untrusted_newlines(tmp_path: Path) -> None:
    output = tmp_path / "github-output.txt"

    _write_outputs(str(output), {"report_path": "report.json\npolicy_pass=false"})

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("report_path<<HOL_GUARD_")
    assert lines[1:3] == ["report.json", "policy_pass=false"]
    assert lines[-1] == lines[0].split("<<", 1)[1]


class _SharingViolationApi:
    def __init__(self, busy_opens: int) -> None:
        self.busy_opens = busy_opens
        self.opens = 0

    def create_file(self, path, access, sharing, creation, flags):
        from codex_plugin_scanner import safe_output_windows

        self.opens += 1
        if self.opens <= self.busy_opens:
            return safe_output_windows._INVALID_HANDLE_VALUE
        return 7

    def inspect_file(self, handle, info):
        info.file_attributes = 0
        return True

    def close_handle(self, handle):
        raise AssertionError("an accepted directory handle must stay open")


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _fake_windows_errors(monkeypatch, error_code: int) -> _FakeClock:
    from codex_plugin_scanner import safe_output_windows

    clock = _FakeClock()
    monkeypatch.setattr(safe_output_windows, "time", clock)
    monkeypatch.setattr(safe_output_windows.ctypes, "get_last_error", lambda: error_code, raising=False)
    monkeypatch.setattr(safe_output_windows.ctypes, "FormatError", lambda code: "in use", raising=False)
    return clock


def test_windows_directory_lock_waits_out_a_short_lived_writer(tmp_path: Path, monkeypatch):
    from codex_plugin_scanner import safe_output_windows

    _fake_windows_errors(monkeypatch, 32)
    api = _SharingViolationApi(busy_opens=3)
    assert safe_output_windows._open_locked_directory(api, tmp_path) == 7
    assert api.opens == 4


def test_windows_directory_lock_gives_up_once_the_wait_is_spent(tmp_path: Path, monkeypatch):
    from codex_plugin_scanner import safe_output_windows

    clock = _fake_windows_errors(monkeypatch, 32)
    api = _SharingViolationApi(busy_opens=1_000)
    with pytest.raises(OSError, match="unable to lock output directory"):
        safe_output_windows._open_locked_directory(api, tmp_path)
    wait = safe_output_windows._SHARING_VIOLATION_WAIT_SECONDS
    assert wait <= clock.now < wait + 0.1
    assert max(clock.sleeps) == 0.1
    assert api.opens == len(clock.sleeps) + 1


def test_windows_directory_lock_does_not_retry_other_errors(tmp_path: Path, monkeypatch):
    from codex_plugin_scanner import safe_output_windows

    clock = _fake_windows_errors(monkeypatch, 5)
    api = _SharingViolationApi(busy_opens=1_000)
    with pytest.raises(OSError, match="unable to lock output directory"):
        safe_output_windows._open_locked_directory(api, tmp_path)
    assert api.opens == 1
    assert clock.sleeps == []
