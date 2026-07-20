"""Security regressions for the authenticated, isolated Codex hook fallback."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
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
    workspace_index = fallback_command.index("--workspace")
    assert fallback_command[workspace_index + 1] == str(workspace)
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
            "import sys;sys.stdout.write('o'*800);sys.stderr.write('e'*800);sys.stdout.flush();sys.stderr.flush()",
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
    assert len(overflow_result.stdout.encode("utf-8")) <= 1024


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group lifetime assertion")
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


@pytest.fixture(autouse=True)
def _restore_current_directory() -> Iterator[None]:
    original = Path.cwd()
    try:
        yield
    finally:
        os.chdir(original)
