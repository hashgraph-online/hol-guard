"""Security regressions for the authenticated, isolated Codex hook fallback."""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch_runtime
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
    isolated_daemon_start_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)
from codex_plugin_scanner.guard.codex_hook_runtime_trust import validate_codex_hook_launch


def _installed_launch(tmp_path: Path) -> tuple[HarnessContext, tuple[str, ...], dict[str, object]]:
    workspace = tmp_path / "workspace with spaces"
    workspace.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home with spaces",
        workspace_dir=workspace,
        guard_home=tmp_path / "Guard home with spaces",
        home_override_explicit=True,
    )
    CodexHarnessAdapter().install(context)
    bridge_command = codex_adapter._hook_command_parts(context)
    config = json.loads(bridge_command[3])
    assert isinstance(config, dict)
    return context, bridge_command, config


def _trusted_launch(bridge_command: tuple[str, ...], config: dict[str, object]):
    return validate_codex_hook_launch(
        manifest_path=str(config["manifest_path"]),
        state_path=str(config["state_path"]),
        fallback_command=_config_command(config, "fallback_command"),
        start_command=_config_command(config, "start_command"),
        config_json=bridge_command[3],
    )


def _config_command(config: dict[str, object], name: str) -> list[str]:
    value = config[name]
    assert isinstance(value, list)
    assert value and all(isinstance(token, str) for token in value)
    return [token for token in value if isinstance(token, str)]


def test_daemon_start_command_keeps_pre_home_argument_compatibility(tmp_path: Path) -> None:
    command = isolated_daemon_start_command(sys.executable, tmp_path, tmp_path / "guard")

    assert f"home_dir=Path({str(Path.home())!r})" in command[3]


def test_fallback_environment_drops_import_virtualenv_project_and_loader_controls(
    tmp_path: Path,
) -> None:
    hostile = {
        "PATH": str(tmp_path / "bin"),
        "HOME": str(tmp_path / "home"),
        "CODEX_HOME": str(tmp_path / "codex"),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "C",
        "PYTHONPATH": str(tmp_path / "python-path"),
        "PYTHONHOME": str(tmp_path / "python-home"),
        "PYTHONSTARTUP": str(tmp_path / "startup.py"),
        "PYTHONINSPECT": "1",
        "PYTHONWARNINGS": "error",
        "PYTHONBREAKPOINT": "attacker.breakpoint",
        "VIRTUAL_ENV": str(tmp_path / ".venv"),
        "UV_PROJECT_ENVIRONMENT": str(tmp_path / "uv-project"),
        "UV_PYTHON": str(tmp_path / "uv-python"),
        "CONDA_PREFIX": str(tmp_path / "conda"),
        "PIP_CONFIG_FILE": str(tmp_path / "pip.conf"),
        "LD_PRELOAD": str(tmp_path / "preload.so"),
        "DYLD_INSERT_LIBRARIES": str(tmp_path / "inject.dylib"),
    }

    environment = isolated_hook_environment(hostile)

    assert environment == {
        "PATH": hostile["PATH"],
        "HOME": hostile["HOME"],
        "CODEX_HOME": hostile["CODEX_HOME"],
        "LANG": hostile["LANG"],
        "LC_ALL": hostile["LC_ALL"],
    }


def test_verified_fallback_ignores_workspace_and_ambient_python_imports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, bridge_command, config = _installed_launch(tmp_path)
    workspace = context.workspace_dir
    assert workspace is not None
    marker = tmp_path / "attacker-imported.marker"
    marker_write = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
    (workspace / "sitecustomize.py").write_text(marker_write, encoding="utf-8")
    (workspace / "codex_plugin_scanner.py").write_text(marker_write, encoding="utf-8")
    fake_package = workspace / "codex_plugin_scanner"
    fake_package.mkdir()
    (fake_package / "__init__.py").write_text(marker_write, encoding="utf-8")
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("PYTHONPATH", str(workspace))
    monkeypatch.setenv("PYTHONSTARTUP", str(workspace / "sitecustomize.py"))
    monkeypatch.setenv("VIRTUAL_ENV", str(workspace / ".venv"))
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", str(workspace))

    trusted = _trusted_launch(bridge_command, config)
    fallback_command = _config_command(config, "fallback_command")
    payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "printf 'payload survives'"},
        },
        separators=(",", ":"),
    )
    fallback_stdout = trusted.run_fallback(fallback_command, data=payload, timeout_seconds=20)

    assert fallback_stdout == ""
    assert trusted.cwd == Path(str(config["manifest_path"])).parent.resolve(strict=True)
    assert trusted.cwd != workspace.resolve()
    assert {"PYTHONPATH", "PYTHONSTARTUP", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT"}.isdisjoint(trusted.environment)
    assert "--workspace" not in fallback_command
    assert fallback_command[:3] == [str(Path(sys.executable).absolute()), "-I", "-c"]
    assert not marker.exists()


@pytest.mark.parametrize("mutation", ["extra-argv", "altered-entrypoint"])
def test_tampered_bridge_launch_contract_fails_closed_without_executing_project_code(
    tmp_path: Path,
    mutation: str,
) -> None:
    context, bridge_command, config = _installed_launch(tmp_path)
    workspace = context.workspace_dir
    assert workspace is not None
    marker = tmp_path / "sitecustomize-executed.marker"
    (workspace / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    fallback_command = _config_command(config, "fallback_command")
    if mutation == "extra-argv":
        fallback_command.append("--attacker-argument")
    else:
        fallback_command[3] = f"from pathlib import Path;Path({str(marker)!r}).write_text('executed')"
    config["fallback_command"] = fallback_command
    tampered_json = json.dumps(config, separators=(",", ":"))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(workspace)
    result = subprocess.run(
        [*bridge_command[:3], tampered_json],
        input=json.dumps({"hook_event_name": "PreToolUse"}),
        capture_output=True,
        text=True,
        cwd=workspace,
        env=environment,
        timeout=10,
        check=False,
    )

    response = json.loads(result.stdout)
    assert result.returncode == 0
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "hol-guard install codex" in result.stdout
    assert result.stderr == ""
    assert not marker.exists()


def test_runtime_rejects_a_manifest_changed_after_install(tmp_path: Path) -> None:
    _context, bridge_command, config = _installed_launch(tmp_path)
    manifest_path = Path(str(config["manifest_path"]))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["package_version"] = "attacker-replacement"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(CodexHookIntegrityError, match="authentication failed"):
        _trusted_launch(bridge_command, config)


@pytest.mark.skipif(os.name == "nt", reason="symlink replacement semantics differ on Windows")
def test_signed_runtime_guard_home_is_canonical_across_directory_aliases(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    alias_root = tmp_path / "alias"
    alias_root.symlink_to(real_root, target_is_directory=True)
    workspace = alias_root / "workspace"
    workspace.mkdir()
    context = HarnessContext(
        home_dir=alias_root / "home",
        workspace_dir=workspace,
        guard_home=alias_root / "guard-home",
        home_override_explicit=True,
    )

    CodexHarnessAdapter().install(context)
    bridge_command = codex_adapter._hook_command_parts(context)
    config = json.loads(bridge_command[3])
    trusted = _trusted_launch(bridge_command, config)
    canonical_guard_home = context.guard_home.resolve(strict=True)

    assert Path(str(config["state_path"])).parent == canonical_guard_home
    assert str(canonical_guard_home) in _config_command(config, "start_command")[3]
    assert trusted.cwd == canonical_guard_home / "managed" / "codex"


@pytest.mark.skipif(os.name == "nt", reason="symlink replacement semantics differ on Windows")
def test_runtime_rejects_interpreter_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter_link = tmp_path / "guard-python"
    interpreter_link.symlink_to(Path(sys.executable).resolve(strict=True))
    replacement = tmp_path / "replacement-python"
    replacement.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    replacement.chmod(0o755)
    monkeypatch.setattr(codex_adapter.sys, "executable", str(interpreter_link))
    _context, bridge_command, config = _installed_launch(tmp_path)
    interpreter_link.unlink()
    interpreter_link.symlink_to(replacement)

    with pytest.raises(CodexHookIntegrityError, match="symlink target changed"):
        _trusted_launch(bridge_command, config)


def test_isolated_process_preserves_exact_input_and_bounds_combined_output(tmp_path: Path) -> None:
    cwd = tmp_path / "neutral"
    cwd.mkdir(mode=0o700)
    payload = "exact input with spaces, unicode: \N{SNOWMAN}\n"
    echo_result = run_isolated_hook_process(
        [sys.executable, "-I", "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        input_text=payload,
        cwd=cwd,
        environment=isolated_hook_environment(),
        timeout_seconds=5,
        output_limit=1024,
    )
    overflow_result = run_isolated_hook_process(
        [
            sys.executable,
            "-I",
            "-c",
            "import os;os.write(1,b'\\xff'*800);os.write(2,b'e'*800)",
        ],
        input_text="",
        cwd=cwd,
        environment=isolated_hook_environment(),
        timeout_seconds=5,
        output_limit=1024,
    )

    assert echo_result.returncode == 0
    assert echo_result.stdout == payload
    assert echo_result.output_limit_exceeded is False
    assert overflow_result.output_limit_exceeded is True
    assert len((overflow_result.stdout + overflow_result.stderr).encode("utf-8")) <= 1024


def test_isolated_process_timeout_kills_descendants(tmp_path: Path) -> None:
    cwd = tmp_path / "neutral"
    cwd.mkdir(mode=0o700)
    marker = tmp_path / "escaped-child.marker"
    child = f"import time;from pathlib import Path;time.sleep(0.5);Path({str(marker)!r}).write_text('escaped')"
    parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-I','-c',{child!r}]);time.sleep(10)"

    result = run_isolated_hook_process(
        [sys.executable, "-I", "-c", parent],
        input_text="",
        cwd=cwd,
        environment=isolated_hook_environment(),
        timeout_seconds=0.1,
    )
    time.sleep(0.6)

    assert result.timed_out is True
    assert not marker.exists()


def test_isolated_process_closes_descendant_held_pipes_after_parent_exit(tmp_path: Path) -> None:
    cwd = tmp_path / "neutral"
    cwd.mkdir(mode=0o700)
    marker = tmp_path / "escaped-after-parent-exit.marker"
    child = f"import time;from pathlib import Path;time.sleep(0.5);Path({str(marker)!r}).write_text('escaped')"
    parent = f"import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c',{child!r}])"

    started_at = time.monotonic()
    result = run_isolated_hook_process(
        [sys.executable, "-I", "-c", parent],
        input_text="",
        cwd=cwd,
        environment=isolated_hook_environment(),
        timeout_seconds=2,
    )
    elapsed = time.monotonic() - started_at
    time.sleep(0.6)

    assert result.returncode == 0
    assert elapsed < 1
    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="Unix resident runtimes use an inherited liveness pipe")
def test_parent_liveness_stops_child_after_supervisor_is_killed(tmp_path: Path) -> None:
    cwd = tmp_path / "neutral"
    cwd.mkdir(mode=0o700)
    child_pid_path = tmp_path / "child.pid"
    child = (
        "import os;from pathlib import Path;"
        f"Path({str(child_pid_path)!r}).write_text(str(os.getpid()));"
        "descriptor=int(os.environ['HOL_GUARD_PARENT_LIVENESS_FD']);"
        "os.fdopen(os.dup(descriptor),'rb',closefd=True).read(1)"
    )
    package_source = Path(launch_runtime.__file__).resolve().parents[2]
    supervisor_code = (
        "import sys;from pathlib import Path;"
        "from codex_plugin_scanner.guard.codex_hook_launch_runtime import "
        "isolated_hook_environment,run_isolated_hook_process;"
        f"run_isolated_hook_process([sys.executable,'-I','-c',{child!r}],"
        f"input_text='',cwd=Path({str(cwd)!r}),environment=isolated_hook_environment(),"
        "timeout_seconds=60,parent_liveness=True)"
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(package_source)
    supervisor = subprocess.Popen(
        [sys.executable, "-c", supervisor_code],
        cwd=cwd,
        env=environment,
    )
    child_pid: int | None = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not child_pid_path.exists():
            time.sleep(0.02)
        assert child_pid_path.exists()
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))

        supervisor.kill()
        supervisor.wait(timeout=5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("child outlived its supervisor liveness pipe")
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        if child_pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_isolated_process_returns_when_tree_termination_cannot_be_confirmed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubbornProcess:
        pid = 987_654
        stdin = io.BytesIO()
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(["stubborn"], timeout if timeout is not None else 0.0)

        def kill(self) -> None:
            raise OSError("kill refused")

    spawns = 0

    def stubborn_popen(*_args: object, **_kwargs: object) -> StubbornProcess:
        nonlocal spawns
        spawns += 1
        return StubbornProcess()

    def refuse_killpg(*_args: object) -> None:
        raise OSError("kill refused")

    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_CONTAINMENT_FAILED", threading.Event())
    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_QUARANTINE", [])
    monkeypatch.setattr(launch_runtime.subprocess, "Popen", stubborn_popen)
    monkeypatch.setattr(launch_runtime.os, "killpg", refuse_killpg)

    started_at = time.monotonic()
    result = run_isolated_hook_process(
        ["stubborn"],
        input_text="",
        cwd=tmp_path,
        environment={},
        timeout_seconds=0,
    )
    elapsed = time.monotonic() - started_at
    latched = run_isolated_hook_process(
        ["must-not-spawn"],
        input_text="",
        cwd=tmp_path,
        environment={},
        timeout_seconds=10,
    )

    assert elapsed < 2
    assert result.returncode is None
    assert result.timed_out is True
    assert result.containment_failed is True
    assert latched.containment_failed is True
    assert spawns == 1


def test_isolated_process_latches_when_input_writer_cannot_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = launch_runtime.subprocess.Popen
    release_writer = threading.Event()

    class BlockingInput:
        def write(self, data: bytes) -> int:
            if not release_writer.wait(timeout=2):
                return 0
            return len(data)

        def flush(self) -> None:
            return

        def close(self) -> None:
            return

    class ExitedProcess:
        pid = 987_654
        stdin = BlockingInput()
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_CONTAINMENT_FAILED", threading.Event())
    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_QUARANTINE", [])
    monkeypatch.setattr(launch_runtime.subprocess, "Popen", lambda *_args, **_kwargs: ExitedProcess())
    monkeypatch.setattr(launch_runtime.os, "killpg", lambda *_args: None)

    started_at = time.monotonic()
    result = run_isolated_hook_process(
        ["exited-with-stuck-writer"],
        input_text="blocked",
        cwd=tmp_path,
        environment={},
        timeout_seconds=1,
    )
    elapsed = time.monotonic() - started_at
    release_writer.set()

    assert elapsed < 1.5
    assert result.returncode is None
    assert result.containment_failed is True
    assert launch_runtime._HOOK_PROCESS_CONTAINMENT_FAILED.is_set()

    monkeypatch.setattr(launch_runtime.subprocess, "Popen", real_popen)
    recovered = run_isolated_hook_process(
        [sys.executable, "-I", "-c", "print('recovered')"],
        input_text="",
        cwd=tmp_path,
        environment=isolated_hook_environment(),
        timeout_seconds=2,
    )

    assert recovered.returncode == 0
    assert recovered.stdout.strip() == "recovered"
    assert launch_runtime._HOOK_PROCESS_CONTAINMENT_FAILED.is_set() is False


def test_quarantine_retry_uses_one_deadline_for_all_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubbornProcess:
        pid = 987_654

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            if timeout:
                time.sleep(timeout)
            raise subprocess.TimeoutExpired(["stubborn"], timeout if timeout is not None else 0.0)

        def kill(self) -> None:
            raise OSError("kill refused")

    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_CONTAINMENT_FAILED", threading.Event())
    quarantined = [
        launch_runtime._QuarantinedHookProcess(cast("subprocess.Popen[bytes]", StubbornProcess()), None, ())
        for _ in range(20)
    ]

    def refuse_killpg(*_args: object) -> None:
        raise OSError("kill refused")

    monkeypatch.setattr(
        launch_runtime,
        "_HOOK_PROCESS_QUARANTINE",
        quarantined,
    )
    monkeypatch.setattr(launch_runtime.os, "killpg", refuse_killpg)

    started_at = time.monotonic()
    recovered = launch_runtime._retry_quarantined_hook_processes()
    elapsed = time.monotonic() - started_at

    assert recovered is False
    assert elapsed < 1.5
    assert len(launch_runtime._HOOK_PROCESS_QUARANTINE) == 20


def test_quarantine_retry_releases_windows_job_handle_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExitedProcess:
        pid = 987_654

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    closed_jobs: list[object] = []
    job = object()
    quarantined = launch_runtime._QuarantinedHookProcess(
        cast("subprocess.Popen[bytes]", ExitedProcess()),
        cast("launch_runtime.WindowsHookJob", job),
        (),
    )
    containment_latch = threading.Event()
    containment_latch.set()
    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_CONTAINMENT_FAILED", containment_latch)
    monkeypatch.setattr(launch_runtime, "_HOOK_PROCESS_QUARANTINE", [quarantined])
    monkeypatch.setattr(launch_runtime, "_kill_hook_process", lambda *_args: True)
    monkeypatch.setattr(launch_runtime, "close_windows_hook_job", closed_jobs.append)

    assert launch_runtime._retry_quarantined_hook_processes() is True
    assert closed_jobs == [job]
    assert quarantined.windows_job is None
    assert launch_runtime._HOOK_PROCESS_CONTAINMENT_FAILED.is_set() is False


@pytest.fixture(autouse=True)
def _restore_current_directory() -> Iterator[None]:
    original = Path.cwd()
    try:
        yield
    finally:
        os.chdir(original)
