from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import cline_hooks as cline_hooks_module
from codex_plugin_scanner.guard.adapters import cline_state_paths as cline_state_paths_module
from codex_plugin_scanner.guard.adapters import guard_cli_attestation
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_hooks import (
    _hook_command,
    _hook_source,
    _posix_wrapper,
    _powershell_wrapper,
    _slot_for_event,
    cline_hook_roots,
    cline_native_hook_state,
    run_cline_hook_canary,
    uninstall_cline_hooks,
)
from codex_plugin_scanner.guard.adapters.cline_plugin import _plugin_source, install_cline_plugin


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _activate(context: HarnessContext, transport: str) -> None:
    path = context.guard_home / "managed" / "cline" / "adapter-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "active_transport": transport}) + "\n", encoding="utf-8")


def _fake_guard(tmp_path: Path) -> Path:
    path = tmp_path / "fake_guard.py"
    path.write_text(
        """from __future__ import annotations
import json, os, sys
payload=json.load(sys.stdin)
log=os.environ.get("CLINE_TEST_LOG")
if log:
    with open(log,"a",encoding="utf-8") as handle: handle.write(json.dumps(payload,sort_keys=True)+"\\n")
text=json.dumps(payload,sort_keys=True)
if "BLOCK_ME" in text or "SECRET_OUTPUT" in text: print(json.dumps({"decision":"block","reason":"blocked by test"}))
else: print(json.dumps({"decision":"allow"}))
""",
        encoding="utf-8",
    )
    return path


def _run_hook(source: str, tmp_path: Path, payload: dict[str, object], *, env=None) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "PreToolUse"
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return subprocess.run(
        [sys.executable, str(path)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        check=False,
    )


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
        [node, "--input-type=module", "-e", code], capture_output=True, text=True, timeout=10, check=False
    )


def test_native_hook_root_matches_vscode_and_core_global_directory(tmp_path: Path) -> None:
    context = _context(tmp_path)
    roots = cline_hook_roots(context)
    assert roots[0] == context.home_dir / "Documents" / "Cline" / "Hooks"
    assert roots[1] == context.home_dir / ".cline" / "hooks"


def test_frozen_cline_plugin_persists_signed_executable_command(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    executable = tmp_path / "HOL Guard"
    executable.write_bytes(b"signed-frozen-core")
    executable.chmod(0o755)
    monkeypatch.setattr(guard_cli_attestation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_cli_attestation.sys, "executable", str(executable))

    manifest = install_cline_plugin(context)
    source = Path(str(manifest["managed_plugin_path"])).read_text(encoding="utf-8")

    assert f"const GUARD_CLI = {json.dumps([str(executable), 'hook'])};" in source
    identity = manifest["guard_cli_identity"]
    assert isinstance(identity, dict)
    assert identity["runtime"] == "frozen-core"
    assert identity["command"] == [str(executable)]


def test_native_hook_slots_are_platform_canonical_and_non_destructive(tmp_path: Path) -> None:
    root = tmp_path / "hooks"
    root.mkdir()
    assert _slot_for_event(root, "PreToolUse", windows=False).name == "PreToolUse"
    assert _slot_for_event(root, "PreToolUse", windows=True).name == "PreToolUse.ps1"
    (root / "PreToolUse").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        _slot_for_event(root, "PreToolUse", windows=False)


def test_posix_wrapper_pins_python_and_isolation_flags() -> None:
    source = _posix_wrapper(worker=Path("/guard/worker.py"), python="/runtime/python")
    assert source.startswith("#!/bin/sh\n")
    assert "exec /runtime/python -I -s /guard/worker.py" in source
    assert "/usr/bin/env python" not in source


def test_windows_wrapper_uses_isolated_python_and_fails_closed() -> None:
    source = _powershell_wrapper(worker=Path("C:/Guard/worker.py"), python="C:/Python/python.exe", blocking=True)
    assert '"-I", "-s"' in source
    assert "ConvertTo-Json -Compress" in source
    assert "cancel=$true" in source


def test_cline_canary_uses_only_the_canonical_managed_slot(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path / "home parent with spaces")
    hook = cline_hook_roots(context)[0] / ("PreToolUse.ps1" if os.name == "nt" else "PreToolUse")
    hook.parent.mkdir(parents=True)
    hook.write_text("# HOL_GUARD_MANAGED_CLINE_HOOK_V1\n", encoding="utf-8")
    if os.name != "nt":
        hook.chmod(0o700)
    state = context.guard_home / "managed" / "cline" / "native-hooks-state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"paths": {"PreToolUse": str(hook)}}), encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["shell"] = kwargs.get("shell")
        return subprocess.CompletedProcess(command, 0, stdout='{"cancel":false}\n', stderr="")

    monkeypatch.setattr(cline_hooks_module.subprocess, "run", fake_run)
    if os.name == "nt":
        powershell = tmp_path / "PowerShell Dir" / "powershell.exe"
        powershell.parent.mkdir()
        powershell.write_bytes(b"")
        monkeypatch.setattr(cline_state_paths_module, "trusted_windows_system_executable", lambda *_parts: powershell)

    assert run_cline_hook_canary(context) == {"ok": True}
    observed_command = observed["command"]
    assert isinstance(observed_command, list)
    assert observed_command[-1] == str(hook.resolve())
    assert observed["shell"] is False


def test_cline_powershell_command_never_uses_ambient_path(tmp_path: Path, monkeypatch) -> None:
    attacker_dir = tmp_path / "attacker-bin"
    attacker_dir.mkdir()
    attacker_shell = attacker_dir / "powershell.exe"
    attacker_shell.write_bytes(b"")
    monkeypatch.setenv("PATH", str(attacker_dir))

    def unavailable_system_shell(*_parts: str) -> Path:
        raise OSError("trusted Windows PowerShell unavailable")

    monkeypatch.setattr(cline_state_paths_module, "trusted_windows_system_executable", unavailable_system_shell)

    assert _hook_command(tmp_path / "PreToolUse.ps1") == []


def test_cline_saved_custom_root_survives_environment_change(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path / "home parent")
    custom_data = context.home_dir / "custom cline data"
    custom_root = custom_data / "hooks"
    monkeypatch.setenv("CLINE_DATA_DIR", str(custom_data))
    paths: dict[str, str] = {}
    digests: dict[str, str] = {}
    workers: dict[str, str] = {}
    worker_digests: dict[str, str] = {}
    for event in cline_hooks_module._EVENTS:
        hook = custom_root / f"{event}{'.ps1' if os.name == 'nt' else ''}"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook_content = "# HOL_GUARD_MANAGED_CLINE_HOOK_V1\n"
        hook.write_text(hook_content, encoding="utf-8")
        worker = context.guard_home / "managed" / "cline" / "hook-workers" / f"{event}.py"
        worker.parent.mkdir(parents=True, exist_ok=True)
        worker_content = "# HOL_GUARD_MANAGED_CLINE_HOOK_V1\n"
        worker.write_text(worker_content, encoding="utf-8")
        paths[event] = str(hook)
        digests[event] = sha256(hook_content.encode()).hexdigest()
        workers[event] = str(worker)
        worker_digests[event] = sha256(worker_content.encode()).hexdigest()
    state_path = context.guard_home / "managed" / "cline" / "native-hooks-state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "root": str(custom_root),
                "paths": paths,
                "sha256": digests,
                "workers": workers,
                "worker_sha256": worker_digests,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("CLINE_DATA_DIR")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout='{"cancel":false}\n', stderr="")

    monkeypatch.setattr(cline_hooks_module.subprocess, "run", fake_run)
    if os.name == "nt":
        powershell = tmp_path / "trusted" / "powershell.exe"
        powershell.parent.mkdir()
        powershell.write_bytes(b"")
        monkeypatch.setattr(cline_state_paths_module, "trusted_windows_system_executable", lambda *_parts: powershell)

    health = cline_native_hook_state(context)
    assert health["installed"] is True
    assert health["integrity_ok"] is True
    assert health["synthetic_canary_ok"] is True
    uninstall = uninstall_cline_hooks(context)
    assert uninstall["complete"] is True
    assert len(uninstall["removed"]) == len(paths) + len(workers)
    assert not custom_root.exists() or not any(custom_root.iterdir())


def test_cline_state_cannot_execute_or_remove_managed_files_outside_canonical_slots(
    tmp_path: Path, monkeypatch
) -> None:
    context = _context(tmp_path)
    attacker_hook = tmp_path / "outside" / "PreToolUse"
    attacker_hook.parent.mkdir()
    attacker_hook.write_text("# HOL_GUARD_MANAGED_CLINE_HOOK_V1\n", encoding="utf-8")
    attacker_hook.chmod(0o700)
    state = context.guard_home / "managed" / "cline" / "native-hooks-state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        json.dumps(
            {
                "paths": {"PreToolUse": str(attacker_hook)},
                "sha256": {"PreToolUse": "attacker-controlled"},
            }
        ),
        encoding="utf-8",
    )

    def fail_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("an unbound Cline state path must not be executed")

    monkeypatch.setattr(cline_hooks_module.subprocess, "run", fail_run)

    assert run_cline_hook_canary(context) == {"ok": False, "reason": "pretool_hook_missing"}
    assert cline_native_hook_state(context)["installed"] is False
    uninstall = uninstall_cline_hooks(context)
    assert uninstall["complete"] is False
    assert str(attacker_hook) in uninstall["retained_modified_or_unowned"]
    assert attacker_hook.exists()


def test_native_pretool_continues_inspection_when_guard_is_unavailable(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[str(tmp_path / "missing")])
    result = _run_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "read_files", "input": {"paths": ["README.md"]}}},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["cancel"] is False


def test_native_pretool_pauses_mutation_when_guard_is_unavailable(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[str(tmp_path / "missing")])
    result = _run_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "run_command", "input": {"command": "rm -rf /"}}},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["cancel"] is True


def test_native_pretool_validates_every_command_when_guard_is_unavailable(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[str(tmp_path / "missing")])
    result = _run_hook(
        source,
        tmp_path,
        {
            "hookName": "PreToolUse",
            "tool_call": {"id": "1", "name": "run_commands", "input": {"commands": ["git status", "rm -rf /"]}},
        },
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["cancel"] is True


def test_native_pretool_fans_out_cline_parallel_commands(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    guard = _fake_guard(tmp_path)
    log = tmp_path / "guard.jsonl"
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    result = _run_hook(
        source,
        tmp_path,
        {
            "hookName": "PreToolUse",
            "tool_call": {"id": "1", "name": "run_commands", "input": {"commands": ["echo safe", "BLOCK_ME"]}},
        },
        env={**os.environ, "CLINE_TEST_LOG": str(log)},
    )
    assert json.loads(result.stdout)["cancel"] is True
    values = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [value["tool_call"]["input"]["command"] for value in values] == ["echo safe", "BLOCK_ME"]


def test_native_pretool_rejects_oversized_input_before_guard(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    guard = _fake_guard(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    result = _run_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "read_files", "input": {"x": "a" * (1024 * 1024)}}},
    )
    assert json.loads(result.stdout)["cancel"] is True


def test_generated_plugin_syntax_pretool_block_and_posttool_replacement(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required")
    syntax_path = tmp_path / "syntax.mjs"
    syntax_path.write_text(source, encoding="utf-8")
    syntax = subprocess.run([node, "--check", str(syntax_path)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr

    before = _run_plugin(
        source,
        tmp_path,
        (
            'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"run_commands"},'
            'input:{commands:["echo safe","BLOCK_ME"]}})'
        ),
    )
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout) == {"skip": True, "reason": "HOL Guard blocked this action."}

    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    output = json.loads(after.stdout)["result"]
    assert output["isError"] is True
    assert output["output"] == "HOL Guard withheld this tool result."
    assert "SECRET_OUTPUT" not in after.stdout
    assert "SECRET_METADATA" not in after.stdout


def test_generated_plugin_withholds_unreviewed_posttool_output(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    source = _plugin_source(context, [sys.executable, "-c", "import sys; sys.exit(3)"])
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    output = json.loads(after.stdout)["result"]
    assert output == {"output": "HOL Guard could not review this tool result, so it was withheld.", "isError": True}
    assert "SECRET_OUTPUT" not in after.stdout
    assert "SECRET_METADATA" not in after.stdout
    proof_path = context.guard_home / "managed" / "cline" / "proofs" / "plugin-posttool.json"
    assert json.loads(proof_path.read_text(encoding="utf-8"))["outcome"] == "withheld"


@pytest.mark.parametrize("state", ["missing", "malformed", "unknown"])
def test_generated_plugin_withholds_posttool_when_transport_is_unavailable(tmp_path: Path, state: str) -> None:
    context = _context(tmp_path)
    if state == "malformed":
        _activate(context, "plugin")
        (context.guard_home / "managed" / "cline" / "adapter-state.json").write_text("{", encoding="utf-8")
    elif state == "unknown":
        _activate(context, "unknown")
    source = _plugin_source(context, [sys.executable, "-c", 'print("{}")'])
    before = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"read_files"},input:{paths:["README.md"]}})',
    )
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout)["skip"] is True
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},'
        'input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {
        "output": "HOL Guard Cline transport state is unavailable, so this tool result was withheld.",
        "isError": True,
    }
    assert "SECRET_OUTPUT" not in after.stdout
    assert "SECRET_METADATA" not in after.stdout
    proof_path = context.guard_home / "managed" / "cline" / "proofs" / "plugin-posttool.json"
    assert json.loads(proof_path.read_text(encoding="utf-8"))["outcome"] == "withheld"


def test_generated_plugin_preserves_guard_block_on_exit_one(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "blocking_guard.py"
    guard.write_text(
        'print(\'{"decision":"block","reason":"REFLECTED_PRIVATE_TOKEN"}\')\nraise SystemExit(1)\n',
        encoding="utf-8",
    )
    source = _plugin_source(context, [sys.executable, str(guard)])
    before = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"read_files"},input:{paths:["README.md"]}})',
    )
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout) == {"skip": True, "reason": "HOL Guard blocked this action."}
    assert "REFLECTED_PRIVATE_TOKEN" not in before.stdout
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},'
        'input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {
        "output": "HOL Guard withheld this tool result.",
        "isError": True,
    }
    assert "REFLECTED_PRIVATE_TOKEN" not in after.stdout
    assert "SECRET_OUTPUT" not in after.stdout
    proof_path = context.guard_home / "managed" / "cline" / "proofs" / "plugin-posttool.json"
    assert json.loads(proof_path.read_text(encoding="utf-8"))["outcome"] == "replaced"


def test_generated_plugin_withholds_unserializable_posttool_output(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    source = _plugin_source(context, [sys.executable, "-c", 'print("{}")'])
    after = _run_plugin(
        source,
        tmp_path,
        '(()=>{const value={secret:"SECRET_OUTPUT"};value.self=value;'
        'return plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},'
        'input:{paths:["README.md"]},result:{output:value,isError:false}})})()',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {
        "output": "HOL Guard could not review this tool result, so it was withheld.",
        "isError": True,
    }
    assert "SECRET_OUTPUT" not in after.stdout


@pytest.mark.parametrize("decision", [{"decision": "allow"}, {"decision": "allow", "policy_action": "allow"}])
def test_generated_plugin_withholds_allow_without_model_output_action(
    tmp_path: Path, decision: dict[str, str]
) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "replacement_guard.py"
    guard.write_text(f"print({json.dumps(decision)!r})\n", encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {
        "output": "HOL Guard did not provide a reviewed output action, so this tool result was withheld.",
        "isError": True,
    }
    assert "SECRET_OUTPUT" not in after.stdout
    assert "SECRET_METADATA" not in after.stdout
    proof_path = context.guard_home / "managed" / "cline" / "proofs" / "plugin-posttool.json"
    assert json.loads(proof_path.read_text(encoding="utf-8"))["outcome"] == "withheld"


@pytest.mark.parametrize(
    ("directive", "expected_output", "expected_error"),
    [
        (
            {"model_output_action": "replace_with_reviewed_excerpt", "reviewed_excerpt": "SAFE_EXCERPT"},
            "SAFE_EXCERPT",
            False,
        ),
        (
            {"model_output_action": "replace_with_reviewed_excerpt"},
            "HOL Guard did not provide the reviewed excerpt, so this tool result was withheld.",
            True,
        ),
        ({"model_output_action": "block"}, "HOL Guard withheld this tool result.", True),
        (
            {"model_output_action": "allow_original", "reviewed_output_sha256": sha256(b"OTHER_OUTPUT").hexdigest()},
            "HOL Guard could not bind its review to this tool result, so it was withheld.",
            True,
        ),
        (
            {"model_output_action": "unexpected"},
            "HOL Guard returned an unsupported output action, so this tool result was withheld.",
            True,
        ),
    ],
)
def test_generated_plugin_obeys_model_output_directive(
    tmp_path: Path, directive: dict[str, str], expected_output: str, expected_error: bool
) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "directive_guard.py"
    guard.write_text(f"print({json.dumps({'decision': 'allow', **directive})!r})\n", encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},'
        'input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {"output": expected_output, "isError": expected_error}
    assert "SECRET_OUTPUT" not in after.stdout
    assert "SECRET_METADATA" not in after.stdout


def test_generated_plugin_binds_allow_original_to_exact_output(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "matching_digest_guard.py"
    decision = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": sha256(b"SAFE_OUTPUT").hexdigest(),
    }
    guard.write_text(f"print({json.dumps(decision)!r})\n", encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},'
        'input:{paths:["README.md"]},result:{output:"SAFE_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {"output": "SAFE_OUTPUT", "isError": False}
    assert "SECRET_METADATA" not in after.stdout


def test_generated_plugin_returns_the_exact_output_reviewed_for_allow_original(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "matching_digest_guard.py"
    decision = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": sha256(b"SAFE_OUTPUT").hexdigest(),
    }
    guard.write_text(f"print({json.dumps(decision)!r})\n", encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    after = _run_plugin(
        source,
        tmp_path,
        "(()=>{let reads=0;const result={get output(){reads+=1;"
        'return reads===1?"SAFE_OUTPUT":"SECRET_OUTPUT";},isError:false};'
        'return plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},'
        'input:{paths:["README.md"]},result}).then(value=>({value,reads}));})()',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout) == {
        "value": {"result": {"output": "SAFE_OUTPUT", "isError": False}},
        "reads": 1,
    }
    assert "SECRET_OUTPUT" not in after.stdout


@pytest.mark.parametrize(
    "decision_json",
    [
        "{}",
        '{"decision":"unknown"}',
        '{"decision":true,"policy_action":"allow"}',
        '{"decision":null,"policy_action":"allow"}',
    ],
)
def test_generated_plugin_rejects_ambiguous_guard_decision(tmp_path: Path, decision_json: str) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "ambiguous_guard.py"
    guard.write_text(f"print({decision_json!r})\n", encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    before = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"read_files"},input:{paths:["README.md"]}})',
    )
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout) == {
        "skip": True,
        "reason": "HOL Guard returned an ambiguous decision; this action was withheld.",
    }
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {
        "output": "HOL Guard could not review this tool result, so it was withheld.",
        "isError": True,
    }
    assert "SECRET_OUTPUT" not in after.stdout


def test_generated_plugin_accepts_explicit_native_pretool_allow_but_withholds_posttool_without_directive(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "allow_guard.py"
    decision = {"continue": True, "policy_action": "allow", "hookSpecificOutput": {"permissionDecision": "allow"}}
    guard.write_text(f"print({json.dumps(decision)!r})\n", encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    before = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"read_files"},input:{paths:["README.md"]}})',
    )
    assert before.returncode == 0, before.stderr
    assert before.stdout.strip() == "undefined"
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SAFE_OUTPUT",isError:false,metadata:{token:"SECRET_METADATA"}}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"] == {
        "output": "HOL Guard did not provide a reviewed output action, so this tool result was withheld.",
        "isError": True,
    }
    assert "SAFE_OUTPUT" not in after.stdout
    assert "SECRET_METADATA" not in after.stdout


def test_generated_plugin_rejects_nonzero_guard_exit_even_with_allow_json(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = tmp_path / "failed_guard.py"
    guard.write_text('print(\'{"decision":"allow"}\')\nraise SystemExit(7)\n', encoding="utf-8")
    source = _plugin_source(context, [sys.executable, str(guard)])
    before = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"read_files"},input:{paths:["README.md"]}})',
    )
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout)["skip"] is True
    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false}})',
    )
    assert after.returncode == 0, after.stderr
    assert json.loads(after.stdout)["result"]["isError"] is True
    assert "SECRET_OUTPUT" not in after.stdout
