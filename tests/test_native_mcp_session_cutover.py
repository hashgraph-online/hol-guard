"""MCP process ownership stays native on every startup outcome."""

import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp as runtime


@pytest.fixture
def launch(monkeypatch, tmp_path):
    proxy = object.__new__(runtime.RuntimeMcpGuardProxy)
    proxy.context = SimpleNamespace(guard_home=tmp_path / "guard", workspace_dir=tmp_path / "workspace")
    proxy.harness = "codex"
    proxy.server_name = "test"
    proxy.command = ["server", "--stdio"]
    proxy._active_runtime_launch_identity = {"verified": True}
    child_env = {"HOME": str(tmp_path / "user"), "PATH": "/usr/bin"}
    monkeypatch.setattr(proxy, "_prepare_launch", lambda: (child_env, child_env, {}))
    monkeypatch.setattr(proxy, "_verify_post_spawn_launch_identity", lambda **_: True)
    clear = Mock()
    monkeypatch.setattr(proxy, "_clear_launch_identity", clear)
    monkeypatch.setattr(runtime, "resolved_runtime_launch_executable", lambda _: "/usr/bin/server")
    opened = Mock(return_value={"status": "opened"})
    closed = Mock()
    monkeypatch.setattr(runtime, "mcp_stdio_session_open_native", opened)
    monkeypatch.setattr(runtime, "mcp_stdio_session_close_native", closed)
    python_spawn = Mock(side_effect=AssertionError("Python child fallback must not run"))
    monkeypatch.setattr(subprocess, "Popen", python_spawn)
    return SimpleNamespace(proxy=proxy, opened=opened, closed=closed, clear=clear, python_spawn=python_spawn)


def test_verified_launch_uses_only_the_native_session(launch):
    process = launch.proxy._start_process()
    assert isinstance(process, runtime._NativeChildProcess)
    args, kwargs = launch.opened.call_args
    assert args[0] == ["/usr/bin/server", "--stdio"]
    assert kwargs["cwd"] == launch.proxy.context.workspace_dir
    assert str(kwargs["home_dir"]) == kwargs["extra_env"]["HOME"]
    launch.closed.assert_not_called()
    launch.python_spawn.assert_not_called()


@pytest.mark.parametrize("response", [None, {"status": "error", "payload": "refused"}])
def test_native_open_failure_cleans_up_without_a_python_fallback(launch, response):
    launch.opened.return_value = response
    with pytest.raises(RuntimeError):
        launch.proxy._start_process()
    launch.closed.assert_called_once_with(
        launch.opened.call_args.kwargs["session_id"], guard_home=launch.proxy.context.guard_home
    )
    launch.clear.assert_called_once()
    launch.python_spawn.assert_not_called()


def test_unverified_executable_is_rejected_before_any_spawn(launch, monkeypatch):
    monkeypatch.setattr(runtime, "resolved_runtime_launch_executable", lambda _: None)
    with pytest.raises(RuntimeError, match="could not be verified"):
        launch.proxy._start_process()
    launch.opened.assert_not_called()
    launch.closed.assert_not_called()
    launch.clear.assert_called_once()
    launch.python_spawn.assert_not_called()


def test_post_spawn_identity_change_closes_the_native_child(launch, monkeypatch):
    monkeypatch.setattr(launch.proxy, "_verify_post_spawn_launch_identity", lambda **_: False)
    with pytest.raises(RuntimeError, match="identity changed"):
        launch.proxy._start_process()
    launch.closed.assert_called_once()
    launch.python_spawn.assert_not_called()


def test_cleanup_transport_failure_preserves_the_original_launch_failure(launch):
    launch.opened.return_value = None
    launch.closed.side_effect = OSError("cleanup unavailable")
    with pytest.raises(RuntimeError, match="authority is unavailable"):
        launch.proxy._start_process()
    launch.clear.assert_called_once()
    launch.python_spawn.assert_not_called()


def test_native_session_open_binds_the_current_proxy_owner(monkeypatch, tmp_path):
    import os

    from codex_plugin_scanner.guard import native_execution

    request = Mock(return_value={"status": "opened"})
    monkeypatch.setattr(native_execution, "_resident_request", request)
    native_execution.mcp_stdio_session_open_native(
        ["/usr/bin/server"], session_id="opaque-owner-proof", guard_home=tmp_path
    )
    assert request.call_args.kwargs["request"]["owner_pid"] == os.getpid()
