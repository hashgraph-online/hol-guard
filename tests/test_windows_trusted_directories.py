from __future__ import annotations

import ntpath
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import windows_paths as windows_paths_module


class _WindowsOSProxy:
    """Expose Windows branching without mutating process-wide ``os.name``."""

    name = "nt"

    def __getattr__(self, name: str):
        return getattr(os, name)


def _fake_directories_runtime(
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[str, object],
) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def fake_answer(request: dict[str, object]) -> dict[str, object] | None:
        requests.append(request)
        op = request["op"]
        return {"paths": answers[op]} if isinstance(op, str) and op in answers else None

    monkeypatch.setattr(windows_paths_module, "os", _WindowsOSProxy())
    monkeypatch.setattr(windows_paths_module, "_directories_answer", fake_answer)
    return requests


def test_trusted_directories_come_from_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_directories_runtime(
        monkeypatch,
        {
            "system_directories": ["C:\\Windows", "C:\\Windows\\System32"],
            "system_executable": ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],
            "user_profile": ["C:\\Users\\guard"],
            "roaming_appdata": ["D:\\Redirected\\Roaming"],
            "local_temp": ["C:\\Users\\guard\\AppData\\Local\\Temp"],
        },
    )

    assert windows_paths_module.trusted_windows_system_directories() == (
        Path("C:\\Windows"),
        Path("C:\\Windows\\System32"),
    )
    assert windows_paths_module.trusted_windows_system_executable(
        "WindowsPowerShell", "v1.0", "powershell.exe"
    ) == Path("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert windows_paths_module.trusted_windows_user_profile() == Path("C:\\Users\\guard")
    assert windows_paths_module.trusted_windows_roaming_appdata() == Path("D:\\Redirected\\Roaming")
    assert windows_paths_module.trusted_windows_local_temp() == Path("C:\\Users\\guard\\AppData\\Local\\Temp")
    assert requests == [
        {"op": "system_directories"},
        {"op": "system_executable", "relative_parts": ["WindowsPowerShell", "v1.0", "powershell.exe"]},
        {"op": "user_profile"},
        {"op": "roaming_appdata"},
        {"op": "local_temp"},
    ]


@pytest.mark.parametrize(
    "paths",
    [None, [], ["C:\\Users\\guard", "C:\\Users\\other"], ["Users\\guard"], [""], [7]],
)
def test_trusted_directories_refuse_malformed_runtime_answers(
    monkeypatch: pytest.MonkeyPatch,
    paths: object,
) -> None:
    _fake_directories_runtime(monkeypatch, {"user_profile": paths})

    with pytest.raises(OSError, match="windows_user_profile_unavailable"):
        windows_paths_module.trusted_windows_user_profile()


@pytest.mark.parametrize(
    "paths",
    [None, ["C:\\Windows"], ["C:\\Windows", "System32"], ["C:\\Windows", "C:\\Windows\\System32", "C:\\"]],
)
def test_system_directories_refuse_malformed_runtime_answers(
    monkeypatch: pytest.MonkeyPatch,
    paths: object,
) -> None:
    _fake_directories_runtime(monkeypatch, {"system_directories": paths})

    with pytest.raises(OSError, match="windows_system_directory_unavailable"):
        windows_paths_module.trusted_windows_system_directories()


def test_trusted_directories_fail_closed_without_the_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_directories_runtime(monkeypatch, {})

    with pytest.raises(OSError, match="windows_roaming_appdata_unavailable"):
        windows_paths_module.trusted_windows_roaming_appdata()
    with pytest.raises(OSError, match="windows_local_temp_unavailable"):
        windows_paths_module.trusted_windows_local_temp()


def test_system_executables_never_ask_for_rooted_parts(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_directories_runtime(monkeypatch, {"system_executable": ["C:\\Windows\\System32\\cmd.exe"]})

    for parts in [(), ("",), ("C:\\Windows\\System32\\cmd.exe",), ("\\\\server\\share\\cmd.exe",)]:
        with pytest.raises(OSError, match="windows_system_executable_untrusted"):
            windows_paths_module.trusted_windows_system_executable(*parts)
    assert requests == []


def test_trusted_directories_are_never_read_off_windows() -> None:
    if os.name == "nt":
        pytest.skip("covered by the native Windows test")
    with pytest.raises(OSError, match="windows_user_profile_unavailable"):
        windows_paths_module.trusted_windows_user_profile()


@pytest.mark.skipif(os.name != "nt", reason="reads the real Windows directories")
def test_native_runtime_reads_the_real_windows_directories() -> None:
    windows_directory, system_directory = windows_paths_module.trusted_windows_system_directories()
    assert ntpath.normcase(str(system_directory.parent)) == ntpath.normcase(str(windows_directory))
    command_processor = windows_paths_module.trusted_windows_system_executable("cmd.exe")
    assert command_processor.parent == system_directory
    assert command_processor.is_file()
    profile = windows_paths_module.trusted_windows_user_profile()
    assert profile.is_dir()
    assert windows_paths_module.trusted_windows_local_temp() == profile / "AppData" / "Local" / "Temp"
    assert windows_paths_module.trusted_windows_roaming_appdata().is_dir()
