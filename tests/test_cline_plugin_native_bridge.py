"""The Cline AgentPlugin reviews tool calls through the bounded hook bridge."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import guard_cli_attestation
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
)
from codex_plugin_scanner.guard.adapters.cline_plugin import _plugin_source, install_cline_plugin

_BEFORE_TOOL = 'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"run_commands"},input:{commands:["ls"]}})'


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _activate_plugin(context: HarnessContext) -> None:
    path = context.guard_home / "managed" / "cline" / "adapter-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "active_transport": "plugin"}) + "\n", encoding="utf-8")


def _offer_native(monkeypatch: pytest.MonkeyPatch, runtime: Path) -> None:
    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=runtime, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=(NATIVE_BOUNDED_HOOK_FEATURE,),
        ),
    )
    monkeypatch.delenv("HOL_GUARD_BOUNDED_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _hook_argv(source: str) -> list[str]:
    prefix = "const GUARD_HOOK_ARGV = "
    line = next(line for line in source.splitlines() if line.startswith(prefix))
    return json.loads(line[len(prefix) :].rstrip(";"))


def _run_plugin(source: str, tmp_path: Path, expression: str) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for the generated Cline plugin contract")
    path = tmp_path / "plugin.mjs"
    path.write_text(source, encoding="utf-8")
    code = (
        'import { pathToFileURL } from "node:url";'
        f"const plugin=(await import(pathToFileURL({json.dumps(str(path))}).href)).default;"
        f"const result=await ({expression});console.log(JSON.stringify(result));"
    )
    return subprocess.run(
        [node, "--input-type=module", "-e", code], capture_output=True, text=True, timeout=30, check=False
    )


def _answering(body: dict[str, object], status: int) -> list[str]:
    return [
        sys.executable,
        "-c",
        f"import sys; sys.stdin.read(); print({json.dumps(json.dumps(body))}); sys.exit({status})",
    ]


@pytest.mark.skipif(os.name != "posix", reason="asserts POSIX paths and hook command syntax")
def test_plugin_reviews_through_the_native_bridge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime)
    context = _context(tmp_path)

    manifest = install_cline_plugin(context)

    argv = _hook_argv(Path(str(manifest["managed_plugin_path"])).read_text(encoding="utf-8"))
    assert argv[:2] == [str(runtime), NATIVE_BOUNDED_HOOK_COMMAND]
    assert argv[3:5] == ["-I", "-c"]
    config = json.loads(argv[6])
    assert config["harness"] == "cline"
    assert config["guard_home"] == str(context.guard_home)
    assert config["timeout_seconds"] == 8
    cli_args = config["cli_args"]
    assert cli_args[:2] == ["guard", "hook"]
    assert cli_args[cli_args.index("--guard-home") + 1] == str(context.guard_home)
    assert cli_args[cli_args.index("--harness") + 1] == "cline"


def test_frozen_plugin_keeps_the_guard_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "HOL Guard"
    executable.write_bytes(b"signed-frozen-core")
    executable.chmod(0o755)
    monkeypatch.setattr(guard_cli_attestation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_cli_attestation.sys, "executable", str(executable))

    manifest = install_cline_plugin(_context(tmp_path))

    argv = _hook_argv(Path(str(manifest["managed_plugin_path"])).read_text(encoding="utf-8"))
    assert argv == [str(executable), "hook", "--harness", "cline", "--json"]


def test_bridge_block_with_exit_two_is_a_guard_block(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate_plugin(context)
    deny = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"}}
    source = _plugin_source(context, [sys.executable], _answering(deny, 2))

    completed = _run_plugin(source, tmp_path, _BEFORE_TOOL)

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"skip": True, "reason": "HOL Guard blocked this action."}


def test_exit_two_without_a_block_fails_closed(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate_plugin(context)
    allow = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
    source = _plugin_source(context, [sys.executable], _answering(allow, 2))

    completed = _run_plugin(source, tmp_path, _BEFORE_TOOL)

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["skip"] is True
    assert "not allowed to proceed" in result["reason"]


def test_bridge_allow_lets_the_tool_run(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate_plugin(context)
    allow = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}
    source = _plugin_source(context, [sys.executable], _answering(allow, 0))

    completed = _run_plugin(source, tmp_path, _BEFORE_TOOL)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() in {"", "undefined"}
