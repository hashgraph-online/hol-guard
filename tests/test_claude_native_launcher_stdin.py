"""Real stalled-input behavior, including the original outer containment boundary."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import command_handler_argv
from codex_plugin_scanner.guard.codex_hook_launch_runtime import _kill_hook_process, _spawn_hook_process
from scripts import native_claude_launcher_pilot as installer
from tests.test_claude_native_launcher_transport import _fixture, binary, owned_interpreter  # noqa: F401


@pytest.mark.parametrize("partial", [b"", b'{"hook_event_name":"PreToolUse","tool_input":'])
def test_stalled_stdin_retains_current_bridge_outer_containment(tmp_path, monkeypatch, partial, request):
    runtime = request.getfixturevalue("binary")
    server, thread, context = _fixture(tmp_path, runtime, monkeypatch, "PreToolUse", "allow")
    outcomes = []
    try:
        installed = ClaudeCodeHarnessAdapter().install(context)
        handler = json.loads(Path(installed["config_path"]).read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
        current_python = command_handler_argv(handler)
        record = installer.install_private_pilot(context, qualification_root=tmp_path)
        candidate = json.loads(record.read_text())["argv"]["PreToolUse"]
        for implementation, argv in (("current_python", current_python), ("native", candidate)):
            began = time.monotonic()
            process, job, liveness = _spawn_hook_process(
                argv,
                cwd=context.workspace_dir,
                environment=dict(os.environ),
                allow_windows_breakaway=False,
                windows_kill_on_job_close=True,
                parent_liveness=False,
            )
            assert liveness is None and process.stdin is not None
            try:
                process.stdin.write(partial)
                process.stdin.flush()
                # The bound current bridge reads synchronously before it can enforce
                # its operation deadline. Keep the writer open beyond 8 s.
                with pytest.raises(subprocess.TimeoutExpired):
                    process.wait(timeout=8.2)
                assert _kill_hook_process(process, job)
                stdout, stderr = process.communicate(timeout=2)
                elapsed = time.monotonic() - began
                assert process.returncode == -9
                assert stdout == stderr == b""
                assert not server.hook_posts and not server.challenges
                assert 8.2 <= elapsed < 11
                outcomes.append(
                    {
                        "implementation": implementation,
                        "stdin_case": "partial" if partial else "empty",
                        "outer_budget_ms": 8200,
                        "elapsed_ms": round(elapsed * 1000, 3),
                        "exit_code": process.returncode,
                        "stdout_bytes": len(stdout),
                        "stderr_bytes": len(stderr),
                        "hook_posts": 0,
                        "identity_challenges": 0,
                        "contained": True,
                        "independent_input_deadline": False,
                    }
                )
            finally:
                if process.poll() is None:
                    _kill_hook_process(process, job)
                    process.communicate(timeout=2)
        report_path = os.environ.get("CLAUDE_PILOT_COMPONENT_EVIDENCE")
        if report_path:
            target = Path(report_path)
            previous = (
                json.loads(target.read_text())
                if target.exists()
                else {
                    "schema": "guard-claude-pilot-stdin-conformance.v1",
                    "scope": "source_component_linux",
                    "installed_artifact": False,
                    "qualification_complete": False,
                    "binary_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                    "cases": [],
                }
            )
            previous["cases"].extend(outcomes)
            target.write_text(json.dumps(previous, indent=2) + "\n")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("character", ["a", "é"])
def test_character_limit_completes_with_writer_still_open(tmp_path, monkeypatch, character, request):
    runtime = request.getfixturevalue("binary")
    server, thread, context = _fixture(tmp_path, runtime, monkeypatch, "PreToolUse", "allow")
    try:
        installed = ClaudeCodeHarnessAdapter().install(context)
        handler = json.loads(Path(installed["config_path"]).read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
        current_python = command_handler_argv(handler)
        record = installer.install_private_pilot(context, qualification_root=tmp_path)
        candidate = json.loads(record.read_text())["argv"]["PreToolUse"]
        prefix = '{"hook_event_name":"PreToolUse","padding":"'
        body = (prefix + character * (1_000_001 - len(prefix))).encode()
        outcomes = []
        for argv in (current_python, candidate):
            process, job, _ = _spawn_hook_process(
                argv,
                cwd=context.workspace_dir,
                environment=dict(os.environ),
                allow_windows_breakaway=False,
                windows_kill_on_job_close=True,
                parent_liveness=False,
            )
            try:
                assert process.stdin is not None
                process.stdin.write(body)
                process.stdin.flush()
                process.wait(timeout=10)
                stdout, stderr = process.communicate(timeout=2)
                assert process.returncode == 0 and stderr == b""
                assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
                assert not server.hook_posts and not server.challenges
                outcomes.append(stdout)
            finally:
                if process.poll() is None:
                    _kill_hook_process(process, job)
                    process.communicate(timeout=2)
        assert outcomes[0] == outcomes[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
