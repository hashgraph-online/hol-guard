from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentFailure,
    ContainmentInput,
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import execute_contained, file_sha256


def _request(workspace: Path, argv: tuple[str, ...]) -> ContainmentRequest:
    output = workspace / "output"
    output.mkdir(exist_ok=True)
    return ContainmentRequest(
        argv=argv,
        cwd=str(workspace),
        environment=(("HOME", str(output)), ("PATH", "/usr/bin:/bin")),
        policy=ContainmentPolicy(str(workspace), (str(output),)),
        inputs=(),
        launch_digest=hashlib.sha256(b"exact-launch").hexdigest(),
        executable_digest=file_sha256(argv[0]),
        operation_id="test",
    )


def test_unsupported_platform_fails_closed(tmp_path: Path) -> None:
    request = _request(tmp_path.resolve(), ("/usr/bin/true",))
    result = execute_contained(request, platform="win32")

    assert result.exit_code is None
    assert result.enforced is False
    assert result.attestation.failure is ContainmentFailure.UNSUPPORTED_PLATFORM


def test_executable_drift_fails_before_spawn(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    executable = workspace / "runner"
    _ = executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = executable.chmod(0o700)
    request = _request(workspace, (str(executable),))
    _ = executable.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")

    result = execute_contained(request)

    assert result.exit_code is None
    assert result.enforced is False
    assert result.attestation.failure is ContainmentFailure.APPLY_FAILED


def test_input_drift_fails_before_spawn(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    source = workspace / "input.txt"
    _ = source.write_text("reviewed", encoding="utf-8")
    request = ContainmentRequest(
        argv=("/usr/bin/true",),
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), ()),
        inputs=(ContainmentInput(str(source), "input.txt", hashlib.sha256(b"reviewed").hexdigest()),),
        launch_digest=hashlib.sha256(b"exact-launch").hexdigest(),
        executable_digest=file_sha256("/usr/bin/true"),
        operation_id="test",
    )
    _ = source.write_text("changed", encoding="utf-8")

    result = execute_contained(request)

    assert result.exit_code is None
    assert result.enforced is False
    assert result.attestation.failure is ContainmentFailure.APPLY_FAILED


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_keeps_bounded_output_inside_ephemeral_snapshot(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    output = workspace / "output"
    request = _request(workspace, ("/bin/sh", "-c", "printf allowed > output/result.txt"))

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code == 0, result.stderr
    assert not (output / "result.txt").exists()


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_denies_external_and_protected_writes(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    _ = workspace.mkdir()
    protected = workspace / ".guard"
    _ = protected.mkdir()
    marker = protected / "state"
    _ = marker.write_text("unchanged", encoding="utf-8")
    external = tmp_path / "external"
    _ = external.write_text("unchanged", encoding="utf-8")
    command = f"printf changed > {external}; printf changed > .guard/state"
    request = _request(workspace, ("/bin/sh", "-c", command))

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code != 0
    assert external.read_text(encoding="utf-8") == "unchanged"
    assert marker.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_denies_protected_reads(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    protected = workspace / ".guard"
    _ = protected.mkdir()
    marker = protected / "credentials.json"
    _ = marker.write_text("synthetic-secret-sentinel", encoding="utf-8")
    request = _request(workspace, ("/bin/sh", "-c", "cat .guard/credentials.json"))

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code != 0
    assert "synthetic-secret-sentinel" not in result.stdout
    assert "synthetic-secret-sentinel" not in result.stderr


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_cannot_read_undeclared_live_workspace_file(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    secret = workspace / "ordinary-private-input.txt"
    _ = secret.write_text("synthetic-secret-sentinel", encoding="utf-8")
    request = _request(workspace, ("/bin/sh", "-c", f"cat {secret}"))

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code != 0
    assert "synthetic-secret-sentinel" not in result.stdout
    assert "synthetic-secret-sentinel" not in result.stderr


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_denies_network_even_for_loopback(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    code = "import socket; socket.socket().bind(('127.0.0.1', 0))"
    request = _request(workspace, ("/usr/bin/python3", "-c", code))

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code != 0


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_denies_sensitive_system_library_reads(tmp_path: Path) -> None:
    sensitive = Path("/Library/Preferences/SystemConfiguration/preferences.plist")
    if not sensitive.is_file():
        pytest.skip("system preference fixture is unavailable")
    request = _request(tmp_path.resolve(), ("/bin/sh", "-c", f"cat {sensitive}"))

    result = execute_contained(request)

    assert result.enforced is True
    assert result.exit_code != 0
    assert result.stdout == ""


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_macos_backend_leaves_no_background_descendant(tmp_path: Path) -> None:
    request = _request(tmp_path.resolve(), ("/bin/sh", "-c", "sleep 30 & printf '%s' $!"))

    result = execute_contained(request)

    assert result.enforced is True
    raw_pid = result.stdout.strip()
    if raw_pid.isdigit():
        child_pid = int(raw_pid)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and _pid_exists(child_pid):
            time.sleep(0.02)
        assert not _pid_exists(child_pid)


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS sandbox backend")
def test_timeout_retains_enforcement_attestation(tmp_path: Path) -> None:
    request = _request(tmp_path.resolve(), ("/bin/sh", "-c", "sleep 5"))

    result = execute_contained(request, timeout_seconds=0.1)

    assert result.enforced is True
    assert result.timed_out is True
    assert result.exit_code is None


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True
