"""Stdio proxy launch-context binding regressions."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.proxy import stdio as stdio_module
from codex_plugin_scanner.guard.proxy.stdio import (
    ProxyLaunchIdentityChangedError,
    StdioGuardProxy,
    _sensitive_read_current_action,
    build_sensitive_read_approval_hash,
)
from codex_plugin_scanner.guard.runtime.approval_context import (
    approval_context_tokens_validation_reason,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_file_read_request_artifact,
    extract_sensitive_file_read_request,
)


class _FakeProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode or 0


def _replace_file(path: Path, content: bytes, *, executable: bool = False) -> None:
    replacement = path.with_name(f"{path.name}.replacement")
    replacement.parent.mkdir(parents=True, exist_ok=True)
    replacement.write_bytes(content)
    if executable:
        replacement.chmod(0o755)
    replacement.replace(path)


def _sensitive_artifact(workspace: Path) -> GuardArtifact:
    request = extract_sensitive_file_read_request("read_file", {"path": ".env"}, cwd=workspace)
    assert request is not None
    return build_file_read_request_artifact(
        harness="codex",
        request=request,
        config_path=str(workspace / ".mcp.json"),
        source_scope="project",
    )


def _pinned_token(proxy: StdioGuardProxy, artifact: GuardArtifact, config: GuardConfig) -> str:
    proxy._start_process()
    launch_identity = proxy._active_launch_identity
    env_values_hash = proxy._active_env_values_hash
    assert launch_identity is not None
    assert env_values_hash is not None
    return build_sensitive_read_approval_hash(
        artifact,
        config=config,
        cwd=proxy.cwd,
        current_action=_sensitive_read_current_action(config, artifact=artifact, harness="codex"),
        server_launch_identity=launch_identity,
        configured_env_values_hash=env_values_hash,
    )


def test_stdio_sensitive_read_binds_pinned_executable_script_and_configured_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = workspace / "python"
    script = workspace / "server.py"
    _replace_file(launcher, b"fake-python-v1\n", executable=True)
    _replace_file(script, b"print('server-v1')\n")
    artifact = _sensitive_artifact(workspace)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    monkeypatch.setattr(stdio_module.subprocess, "Popen", lambda *_args, **_kwargs: _FakeProcess())

    def proxy(env_value: str) -> StdioGuardProxy:
        return StdioGuardProxy(
            [str(launcher), "server.py"],
            cwd=workspace,
            guard_config=config,
            harness="codex",
            env={"MCP_CONFIGURED_TOKEN": env_value},
        )

    secret_v1 = "stdio-secret-one"
    secret_v2 = "stdio-secret-two"
    baseline_proxy = proxy(secret_v1)
    baseline = _pinned_token(baseline_proxy, artifact, config)
    unchanged = _pinned_token(proxy(secret_v1), artifact, config)
    assert baseline == unchanged

    _replace_file(script, b"print('server-v2')\n")
    script_changed = _pinned_token(proxy(secret_v1), artifact, config)
    assert approval_context_tokens_validation_reason(baseline, script_changed) == ("approval_reuse_identity_changed")

    _replace_file(script, b"print('server-v1')\n")
    _replace_file(launcher, b"fake-python-v2\n", executable=True)
    executable_changed = _pinned_token(proxy(secret_v1), artifact, config)
    assert approval_context_tokens_validation_reason(baseline, executable_changed) == (
        "approval_reuse_identity_changed"
    )

    _replace_file(launcher, b"fake-python-v1\n", executable=True)
    env_changed_proxy = proxy(secret_v2)
    env_changed = _pinned_token(env_changed_proxy, artifact, config)
    assert approval_context_tokens_validation_reason(baseline, env_changed) == ("approval_reuse_identity_changed")
    serialized_context = repr(
        {
            "launch": env_changed_proxy._active_launch_identity,
            "env_hash": env_changed_proxy._active_env_values_hash,
        }
    )
    assert secret_v1 not in serialized_context
    assert secret_v2 not in serialized_context


def test_stdio_launch_identity_change_during_spawn_is_quarantined_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = workspace / "python"
    script = workspace / "server.py"
    _replace_file(launcher, b"fake-python\n", executable=True)
    _replace_file(script, b"print('before-spawn')\n")
    proxy = StdioGuardProxy([str(launcher), "server.py"], cwd=workspace, env={"TOKEN": "one"})
    spawned = _FakeProcess()

    def mutate_during_spawn(*_args: object, **_kwargs: object) -> _FakeProcess:
        _replace_file(script, b"print('after-spawn')\n")
        return spawned

    monkeypatch.setattr(stdio_module.subprocess, "Popen", mutate_during_spawn)
    with pytest.raises(ProxyLaunchIdentityChangedError, match="launch identity changed"):
        proxy._start_process()
    assert spawned.terminated is True
    assert spawned.killed is False
    assert proxy._active_launch_identity is None
    assert proxy._active_env_values_hash is None


def test_stdio_launches_canonical_executable_and_rejects_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original = workspace / "original-server"
    replacement = workspace / "replacement-server"
    launcher = workspace / "server"
    _replace_file(original, b"#!/bin/sh\nwhile :; do :; done\n", executable=True)
    _replace_file(replacement, b"#!/bin/sh\n# replacement\nwhile :; do :; done\n", executable=True)
    launcher.symlink_to(original)
    proxy = StdioGuardProxy([str(launcher)], cwd=workspace)
    real_popen = subprocess.Popen
    observed: dict[str, Any] = {}

    def swap_then_spawn(*args: Any, **kwargs: Any) -> subprocess.Popen[str]:
        observed["executable"] = kwargs.get("executable")
        launcher.unlink()
        launcher.symlink_to(replacement)
        process = real_popen(*args, **kwargs)
        observed["process"] = process
        return process

    monkeypatch.setattr(stdio_module.subprocess, "Popen", swap_then_spawn)
    with pytest.raises(ProxyLaunchIdentityChangedError, match="launch identity changed"):
        proxy._start_process()

    process = observed["process"]
    assert isinstance(process, real_popen)
    assert observed["executable"] == str(original.resolve())
    assert process.poll() is not None
    assert proxy._active_launch_identity is None


def test_stdio_rejects_real_interpreted_entrypoint_swap_before_traffic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    script = workspace / "server.py"
    _replace_file(script, b"import time\ntime.sleep(60)\n")
    proxy = StdioGuardProxy([sys.executable, str(script)], cwd=workspace)
    real_popen = subprocess.Popen
    observed: dict[str, subprocess.Popen[str]] = {}

    def mutate_then_spawn(*args: Any, **kwargs: Any) -> subprocess.Popen[str]:
        _replace_file(script, b"import time\n# changed\ntime.sleep(60)\n")
        process = real_popen(*args, **kwargs)
        observed["process"] = process
        return process

    monkeypatch.setattr(stdio_module.subprocess, "Popen", mutate_then_spawn)
    with pytest.raises(ProxyLaunchIdentityChangedError, match="launch identity changed"):
        proxy._start_process()

    assert observed["process"].poll() is not None
    assert proxy._active_launch_identity is None


def test_stdio_launch_identity_is_cleared_on_spawn_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = workspace / "python"
    script = workspace / "server.py"
    _replace_file(launcher, b"fake-python\n", executable=True)
    _replace_file(script, b"print('server')\n")

    failing_proxy = StdioGuardProxy([str(launcher), "server.py"], cwd=workspace, env={"TOKEN": "one"})

    def fail_spawn(*_args: object, **_kwargs: object) -> _FakeProcess:
        raise OSError("spawn failed")

    monkeypatch.setattr(stdio_module.subprocess, "Popen", fail_spawn)
    with pytest.raises(OSError, match="spawn failed"):
        failing_proxy._start_process()
    assert failing_proxy._active_launch_identity is None
    assert failing_proxy._active_env_values_hash is None
