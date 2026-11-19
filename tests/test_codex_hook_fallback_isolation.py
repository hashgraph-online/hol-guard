"""Security regressions for the authenticated, isolated Codex hook fallback."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_harness_client as codex_adapter
from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch_runtime
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
    isolated_daemon_start_command,
    isolated_hook_environment,
    run_isolated_hook_process,
)
from codex_plugin_scanner.guard.codex_hook_runtime_trust import validate_codex_hook_launch
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests import harness_ops_support as harness_support


def _installed_launch(tmp_path: Path) -> tuple[HarnessContext, tuple[str, ...], dict[str, object]]:
    workspace = tmp_path / "workspace with spaces"
    workspace.mkdir(parents=True)
    context = HarnessContext(
        home_dir=tmp_path / "home with spaces",
        workspace_dir=workspace,
        guard_home=tmp_path / "Guard home with spaces",
        home_override_explicit=True,
    )
    harness_support.install("codex", context)
    bridge_command = codex_adapter._hook_command_parts(context)
    config = json.loads(bridge_command[-1])
    assert isinstance(config, dict)
    return context, bridge_command, config


def _trusted_launch(bridge_command: tuple[str, ...], config: dict[str, object]):
    return validate_codex_hook_launch(
        manifest_path=str(config["manifest_path"]),
        state_path=str(config["state_path"]),
        fallback_command=_config_command(config, "fallback_command"),
        start_command=_config_command(config, "start_command"),
        config_json=bridge_command[-1],
    )


def _config_command(config: dict[str, object], name: str) -> list[str]:
    value = config[name]
    assert isinstance(value, list)
    assert value and all(isinstance(token, str) for token in value)
    return [token for token in value if isinstance(token, str)]


def test_daemon_start_command_keeps_pre_home_argument_compatibility(tmp_path: Path) -> None:
    command = isolated_daemon_start_command(sys.executable, tmp_path, tmp_path / "guard")
    assert f"home_dir=Path({str(Path.home())!r})" in command[3]
    assert "schedule_guard_daemon_recovery" in command[3]


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
        "HOL_GUARD_DESKTOP": "1",
        "HOL_GUARD_DESKTOP_HOOK_PROXY": str(tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "HOL Guard"),
        "HOL_GUARD_DESKTOP_RUNTIME_OWNER": str(tmp_path / "untrusted-runtime-owner"),
    }

    environment = isolated_hook_environment(hostile)

    assert environment == {
        "PATH": hostile["PATH"],
        "HOME": hostile["HOME"],
        "CODEX_HOME": hostile["CODEX_HOME"],
        "LANG": hostile["LANG"],
        "LC_ALL": hostile["LC_ALL"],
        "HOL_GUARD_DESKTOP": hostile["HOL_GUARD_DESKTOP"],
        "HOL_GUARD_DESKTOP_HOOK_PROXY": hostile["HOL_GUARD_DESKTOP_HOOK_PROXY"],
    }


@pytest.mark.usefixtures("native_hook_force")
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
    proxy = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "HOL Guard"
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(tmp_path / "untrusted-runtime-owner"))

    trusted = _trusted_launch(bridge_command, config)
    assert trusted.environment["HOL_GUARD_DESKTOP"] == "1"
    assert trusted.environment["HOL_GUARD_DESKTOP_HOOK_PROXY"] == str(proxy)
    assert "HOL_GUARD_DESKTOP_RUNTIME_OWNER" not in trusted.environment
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

    fallback_output = json.loads(fallback_stdout)
    assert fallback_output["hookSpecificOutput"]["permissionDecision"] == "allow"
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
        [*bridge_command[:2], tampered_json],
        input=json.dumps({"hook_event_name": "PreToolUse"}),
        capture_output=True,
        text=True,
        cwd=workspace,
        env=environment,
        timeout=10,
        check=False,
    )

    # The bridge authenticates the registration against its manifest before it
    # launches anything, so a rewritten argv denies without running. The
    # separate stderr evidence document the Python review path wrote is
    # retired; the denial itself is the record.
    response = json.loads(result.stdout)
    assert result.returncode == 0
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert str(marker) not in result.stderr
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

    harness_support.install("codex", context)
    bridge_command = codex_adapter._hook_command_parts(context)
    config = json.loads(bridge_command[-1])
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
    monkeypatch.setattr(sys, "executable", str(interpreter_link))
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


@pytest.fixture(autouse=True)
def _restore_current_directory() -> Iterator[None]:
    original = Path.cwd()
    try:
        yield
    finally:
        os.chdir(original)
