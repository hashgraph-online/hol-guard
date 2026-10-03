"""Original deadlines must include command resolution and child launch."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source


def _hook_namespace(tmp_path: Path) -> dict:
    context = HarnessContext(home_dir=tmp_path, guard_home=tmp_path / "guard", workspace_dir=None)
    context.guard_home.mkdir()
    source = cursor_hook_script_source(context, guard_cli=[sys.executable], recovery_command=[sys.executable])
    namespace = {"__name__": "deadline_fixture"}
    exec(compile(source, "generated-cursor-hook", "exec"), namespace)
    return namespace


@pytest.mark.parametrize("stdlib", [False, True])
def test_fallback_does_not_launch_after_resolution_consumes_original_budget(tmp_path, stdlib):
    namespace = _hook_namespace(tmp_path)
    if stdlib:
        namespace["run_isolated_hook_process"] = None
    marker = tmp_path / "unexpected-child.marker"
    deadline = time.monotonic() + 0.05

    def resolve_after_deadline():
        time.sleep(max(0, deadline - time.monotonic()) + 0.02)
        return [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('launched')"]

    namespace["_resolved_guard_cli"] = resolve_after_deadline
    with pytest.raises(subprocess.TimeoutExpired):
        namespace["_run_guard_fallback"]([], payload_json="{}", guard_env={}, deadline_monotonic=deadline)
    assert not marker.exists()


def test_contained_launch_uses_only_budget_remaining_after_spawn(tmp_path):
    namespace = _hook_namespace(tmp_path)
    real_popen = namespace["subprocess"].Popen
    marker = tmp_path / "child-completed.marker"
    argv = [
        sys.executable,
        "-c",
        f"import time; time.sleep(0.1); from pathlib import Path; Path({str(marker)!r}).write_text('completed')",
    ]
    original_deadline = time.monotonic() + 0.1

    def delayed_spawn(*args, **kwargs):
        time.sleep(max(0, original_deadline - time.monotonic()) + 0.02)
        return real_popen(*args, **kwargs)

    from unittest.mock import patch

    with patch.object(namespace["subprocess"], "Popen", delayed_spawn), pytest.raises(subprocess.TimeoutExpired):
        namespace["_run_contained_cli"](argv, input_text="", env={}, timeout_seconds=0.15)
    assert not marker.exists()


def test_expired_isolated_budget_returns_timeout_without_spawning(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import codex_hook_launch_runtime as runtime

    def refuse_spawn(*args, **kwargs):
        pytest.fail("An expired operation must not create a new child")

    monkeypatch.setattr(runtime, "_spawn_hook_process", refuse_spawn)
    result = runtime.run_isolated_hook_process(
        [sys.executable], cwd=tmp_path, environment={}, input_text="", deadline_monotonic=time.monotonic() - 1
    )
    assert result.timed_out is True
    assert result.output_limit_exceeded is False


def test_expired_denial_does_not_import_availability_evaluator(tmp_path, monkeypatch):
    import builtins

    namespace = _hook_namespace(tmp_path)
    original_import = builtins.__import__
    evaluator_imports = []

    def tracked_import(name, *args, **kwargs):
        if name == "codex_plugin_scanner.guard.daemon.hook_availability_policy":
            evaluator_imports.append(name)
            raise ImportError("The exhausted operation cannot load another evaluator")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", tracked_import)
    response, exit_code = namespace["_cursor_availability_response"](
        {},
        hook_event_name="beforeReadFile",
        workspace=str(tmp_path),
        deadline_monotonic=time.monotonic() - 1,
    )
    assert response["permission"] == "deny"
    assert exit_code == 2
    assert evaluator_imports == []


def test_expired_fallback_does_not_resolve_executable_identity(tmp_path):
    namespace = _hook_namespace(tmp_path)

    def refuse_resolution():
        pytest.fail("An expired hook must not inspect another executable")

    namespace["_resolved_guard_cli"] = refuse_resolution
    with pytest.raises(subprocess.TimeoutExpired):
        namespace["_run_guard_fallback"]([], payload_json="{}", guard_env={}, deadline_monotonic=time.monotonic() - 1)


def test_expired_rpc_does_not_read_daemon_authority(tmp_path, monkeypatch):
    namespace = _hook_namespace(tmp_path)

    def refuse_read(*args, **kwargs):
        pytest.fail("An expired RPC must not read daemon files")

    monkeypatch.setattr(Path, "read_text", refuse_read)
    assert namespace["_daemon_hook_result"]("{}", deadline_monotonic=time.monotonic() - 1, workspace=None) == (
        None,
        "timeout",
    )


@pytest.mark.parametrize(
    "partial,event,code",
    [
        ("", "beforeShellExecution", 2),
        ('{"hook_event_name":"beforeShellExecution"', "beforeShellExecution", 2),
        ("", "afterShellExecution", 0),
    ],
)
def test_open_input_pipe_cannot_extend_hook_deadline(tmp_path, partial, event, code):
    context = HarnessContext(home_dir=tmp_path, guard_home=tmp_path / "guard", workspace_dir=None)
    source = cursor_hook_script_source(context, guard_cli=[sys.executable], recovery_command=[sys.executable])
    source = source.replace("GUARD_HOOK_TIMEOUT_SECONDS = 42", "GUARD_HOOK_TIMEOUT_SECONDS = 0.15", 1)
    script = tmp_path / "cursor-hook.py"
    script.write_text(source)
    process = subprocess.Popen(
        [sys.executable, "-S", str(script), "--cursor-hook-event", event],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    try:
        if partial:
            process.stdin.write(partial)
            process.stdin.flush()
        process.wait(timeout=2)
        # The producer deliberately keeps stdin open; the child owns its deadline.
        out, err = process.communicate(timeout=1)
        assert process.returncode == code, err
        response = json.loads(out)
        if code == 0:
            assert response == {}
        else:
            assert response["permission"] == "deny"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=1)


@pytest.mark.parametrize("data", [b'{"command":"echo hi"}', b"x" * 1_000_000])
def test_closed_hook_input_preserves_bytes_within_limit(tmp_path, monkeypatch, data):
    namespace = _hook_namespace(tmp_path)
    input_path = tmp_path / "input"
    input_path.write_bytes(data)
    with input_path.open("r", encoding="utf-8") as stream:
        monkeypatch.setattr(sys, "stdin", stream)
        assert namespace["_read_hook_input"](time.monotonic() + 1) == data.decode("utf-8")


@pytest.mark.parametrize("data,error", [(b"x" * 1_000_001, ValueError), (b"\xff", UnicodeDecodeError)])
def test_invalid_hook_input_is_rejected_before_evaluation(tmp_path, monkeypatch, data, error):
    namespace = _hook_namespace(tmp_path)
    input_path = tmp_path / "input"
    input_path.write_bytes(data)
    with input_path.open("r", encoding="utf-8") as stream:
        monkeypatch.setattr(sys, "stdin", stream)
        with pytest.raises(error):
            namespace["_read_hook_input"](time.monotonic() + 1)
