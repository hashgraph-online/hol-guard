from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli import windows_arm64_python as arm64
from tests.update_context_test_support import (
    build_legacy_status_distribution,
    build_legacy_update_context,
    stage_legacy_wheel,
)

X64_PYTHON = r"C:\Program Files\Python313\python.exe"
ARM64_PYTHON = r"C:\Program Files\Python313-arm64\python.exe"
PY_LAUNCHER_LISTING = f" -V:3.13-arm64 *    {ARM64_PYTHON}\n -V:3.13         {X64_PYTHON}\n"
CRYPTOGRAPHY_BUILD_FAILURE = (
    "Building wheel for cryptography (pyproject.toml): finished with status 'error'\n"
    "error: can't find Rust compiler\n"
    "ERROR: Failed building wheel for cryptography\n"
    "ERROR: Failed to build installable wheels for some pyproject.toml based projects (cryptography)\n"
)


@pytest.fixture(autouse=True)
def _use_legacy_update_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"test-runtime")
    runtime.chmod(0o700)
    monkeypatch.setattr(update_commands, "build_trusted_update_context", build_legacy_update_context)
    monkeypatch.setattr(update_commands, "_status_installed_distribution", build_legacy_status_distribution)
    monkeypatch.setattr(update_commands, "stage_trusted_wheel", stage_legacy_wheel)
    monkeypatch.setattr(update_commands, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(update_commands, "resolve_guard_home", lambda: tmp_path / "guard-home")
    monkeypatch.setattr(update_commands, "_retire_native_resident_before_update", lambda _guard_home: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.741")
    monkeypatch.setattr(update_commands, "_current_version_from_subprocess", lambda *_args, **_kwargs: "2.0.741")
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.749")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.shutil,
        "which",
        lambda name: "/mock-home/.local/bin/hol-guard" if name == "hol-guard" else None,
    )


def _python_platform(monkeypatch: pytest.MonkeyPatch, python_platform: str) -> None:
    monkeypatch.setattr(arm64, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(arm64, "sysconfig", SimpleNamespace(get_platform=lambda: python_platform))


def _fake_installer(probes: list[list[str]]):
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command == ["py", "-0p"]:
            probes.append(command)
            return subprocess.CompletedProcess(command, 0, PY_LAUNCHER_LISTING, "")
        if command[0] == X64_PYTHON:
            probes.append(command)
            return subprocess.CompletedProcess(command, 0, "win-amd64\n", "")
        assert command[:4] == ["pipx", "runpip", "hol-guard", "install"]
        return subprocess.CompletedProcess(command, 1, "", CRYPTOGRAPHY_BUILD_FAILURE)

    return fake_run


def test_update_on_native_arm64_python_names_the_x64_python_route(monkeypatch: pytest.MonkeyPatch) -> None:
    _python_platform(monkeypatch, "win-arm64")
    probes: list[list[str]] = []
    monkeypatch.setattr(update_commands.subprocess, "run", _fake_installer(probes))

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "blocked"
    assert payload["changed"] is False
    assert payload["reason_code"] == "update_windows_arm64_x64_python_required"
    assert "retry_command" not in payload
    message = str(payload["message"])
    assert "native Windows ARM64 Python" in message
    assert f'pipx install --force --python "{X64_PYTHON}" hol-guard' in message
    assert ARM64_PYTHON not in message
    assert [probe[0] for probe in probes] == ["py", X64_PYTHON]


def test_update_on_x64_python_keeps_the_generic_installer_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _python_platform(monkeypatch, "win-amd64")
    probes: list[list[str]] = []
    monkeypatch.setattr(update_commands.subprocess, "run", _fake_installer(probes))

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["reason_code"] == "update_installer_failed"
    assert probes == []


@pytest.mark.parametrize(
    ("os_platform", "python_platform", "expected"),
    (("win32", "win-arm64", True), ("win32", "win-amd64", False), ("darwin", "win-arm64", False)),
)
def test_native_windows_arm64_python_reads_the_interpreter_platform(
    os_platform: str, python_platform: str, expected: bool
) -> None:
    assert arm64.native_windows_arm64_python(os_platform=os_platform, python_platform=python_platform) is expected


@pytest.mark.parametrize(
    ("output", "expected"),
    (
        (CRYPTOGRAPHY_BUILD_FAILURE, True),
        ("  x Failed to build `rfc3161-client==1.0.9`\n", True),
        (
            "Collecting cryptography>=50\n  Preparing metadata (pyproject.toml) ... error\n"
            "error: metadata-generation-failed\n",
            True,
        ),
        ("Failed to build installable wheels for some pyproject.toml based projects (pyyaml, rfc3161_client)\n", True),
        (
            "Collecting rfc3161-client>=1\n  Preparing metadata (pyproject.toml): finished with status 'error'\n",
            True,
        ),
        ("ERROR: Failed building wheel for pyyaml\n", False),
        ("Requirement already satisfied: cryptography>=50\nERROR: Failed building wheel for pyyaml\n", False),
        (
            "Collecting cryptography>=50\n  Using cached cryptography-50.0.2-cp311-abi3-win_amd64.whl\n"
            "Collecting pyyaml\n  Preparing metadata (pyproject.toml) ... error\n",
            False,
        ),
        ("ERROR: Could not find a version that satisfies cryptography>=50\n", False),
    ),
)
def test_wheel_less_dependency_build_failed_needs_a_build_failure_for_those_packages(
    output: str, expected: bool
) -> None:
    assert arm64.wheel_less_dependency_build_failed(output) is expected


def test_x64_candidates_skip_arm64_and_32_bit_and_confirm_each_platform() -> None:
    x86_python = r"C:\Python312-32\python.exe"
    mislabeled = r"C:\Python311\python.exe"
    listing = f"{PY_LAUNCHER_LISTING} -V:3.12-32       {x86_python}\n -V:3.11         {mislabeled}\n"
    probed: list[str] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command == ["py", "-0p"]:
            return subprocess.CompletedProcess(command, 0, listing, "")
        probed.append(command[0])
        platform = "win-amd64" if command[0] == X64_PYTHON else "win-arm64"
        return subprocess.CompletedProcess(command, 0, platform + "\n", "")

    assert arm64.x64_python_candidates(fake_run) == [X64_PYTHON]
    assert probed == [X64_PYTHON, mislabeled]


def test_x64_candidates_return_nothing_without_the_py_launcher() -> None:
    def missing_launcher(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    assert arm64.x64_python_candidates(missing_launcher) == []


def test_route_message_without_x64_python_points_at_the_64_bit_installer() -> None:
    message = arm64.x64_python_route_message("uv", [])

    assert 'uv tool install --force --python "<path-to-x64-python.exe>" hol-guard' in message
    assert "Windows installer (64-bit)" in message


def test_route_message_for_pip_upgrades_an_existing_x64_install() -> None:
    message = arm64.x64_python_route_message("pip", [X64_PYTHON])

    assert f'"{X64_PYTHON}" -m pip install --upgrade hol-guard' in message
    assert "the ARM64 environment is not converted" in message
