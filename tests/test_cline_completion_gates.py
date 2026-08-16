from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline import ClineHarnessAdapter
from codex_plugin_scanner.guard.adapters.cline_hooks import _hook_source
from codex_plugin_scanner.guard.adapters.cline_plugin import _plugin_source, cline_plugin_state
from codex_plugin_scanner.guard.adapters.contracts import contract_for
from codex_plugin_scanner.guard.cli.commands_support_interaction import _apps_disconnect_confirm_command
from codex_plugin_scanner.guard.cli.install_commands import build_harness_verification
from codex_plugin_scanner.guard.product_model import (
    CANONICAL_HARNESS_VALUES,
    SUPPORTED_HARNESS_VALUES,
    export_product_model_v1,
)


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
    path = tmp_path / "guard.py"
    path.write_text(
        """from __future__ import annotations
import json, sys
payload=json.load(sys.stdin)
text=json.dumps(payload, sort_keys=True)
if 'BLOCK_ME' in text or 'SECRET_OUTPUT' in text:
    print(json.dumps({'decision':'block','reason':'blocked by completion gate'}))
else:
    print(json.dumps({'decision':'allow'}))
""",
        encoding="utf-8",
    )
    return path


def _run_native(source: str, tmp_path: Path, payload: dict[str, object]) -> dict[str, object]:
    worker = tmp_path / "native.py"
    worker.write_text(source, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(worker)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _run_plugin(source: str, tmp_path: Path, expression: str) -> object:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for generated Cline plugin completion gates")
    plugin = tmp_path / "plugin.mjs"
    plugin.write_text(source, encoding="utf-8")
    code = (
        'import { pathToFileURL } from "node:url";'
        f"const plugin=(await import(pathToFileURL({json.dumps(str(plugin))}).href)).default;"
        f"const result=await ({expression});console.log(JSON.stringify(result ?? null));"
    )
    result = subprocess.run([node, "--input-type=module", "-e", code], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_cline_is_in_static_supported_contracts() -> None:
    contract = contract_for("cline")
    assert contract is not None
    assert contract_for("cline-cli") is contract
    assert contract_for("cline-vscode") is contract
    assert contract.surface_capabilities == ("auto", "hooks", "plugin", "cli", "all")
    assert "cline" in CANONICAL_HARNESS_VALUES
    assert "cline" in SUPPORTED_HARNESS_VALUES


def test_checked_product_schema_matches_exported_cline_membership() -> None:
    schema_path = (
        Path(__file__).parents[1] / "src" / "codex_plugin_scanner" / "guard" / "schemas" / "guard_product_model_v1.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    exported = export_product_model_v1()
    assert schema["canonical_harnesses"] == exported["canonical_harnesses"]
    assert schema["supported_harnesses"] == exported["supported_harnesses"]
    assert "cline" in schema["canonical_harnesses"]
    assert "cline" in schema["supported_harnesses"]


def test_apps_parser_accepts_every_cline_transport_surface() -> None:
    parser = _build_parser("hol-guard", program_mode="hol-guard")
    for action in ("connect", "test", "repair", "disconnect"):
        for surface in ("auto", "hooks", "plugin", "cli", "all"):
            args = parser.parse_args(["apps", action, "cline", "--surface", surface])
            assert args.harness == "cline"
            assert args.surface == surface


def test_disconnect_confirmation_preserves_exact_cline_surface() -> None:
    command = _apps_disconnect_confirm_command("cline", "REMOVE-cline", surface="plugin")
    assert command == "hol-guard apps disconnect cline --surface plugin --confirm REMOVE-cline"


def test_native_proof_requires_actual_block_outcome(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    guard = _fake_guard(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    allowed = _run_native(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "run_command", "input": {"command": "echo safe"}}},
    )
    assert allowed["cancel"] is False
    proof_path = context.guard_home / "managed" / "cline" / "proofs" / "native-pretooluse.json"
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    assert proof["source"] == "cline"
    assert proof["outcome"] == "allowed"

    blocked = _run_native(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "run_command", "input": {"command": "BLOCK_ME"}}},
    )
    assert blocked["cancel"] is True
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    assert proof["outcome"] == "blocked"


def test_plugin_proofs_distinguish_allow_block_and_replacement(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])

    assert (
        _run_plugin(
            source,
            tmp_path,
            (
                'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"run_commands"},'
                'input:{commands:["echo safe"]}})'
            ),
        )
        is None
    )
    pre_path = context.guard_home / "managed" / "cline" / "proofs" / "plugin-pretool.json"
    assert json.loads(pre_path.read_text(encoding="utf-8"))["outcome"] == "allowed"

    blocked = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"2",toolName:"run_commands"},input:{commands:["BLOCK_ME"]}})',
    )
    assert isinstance(blocked, dict) and blocked["skip"] is True
    assert json.loads(pre_path.read_text(encoding="utf-8"))["outcome"] == "blocked"

    assert (
        _run_plugin(
            source,
            tmp_path,
            (
                'plugin.hooks.beforeTool({toolCall:{toolCallId:"2b",toolName:"run_commands"},'
                'input:{commands:["echo safe again"]}})'
            ),
        )
        is None
    )
    assert json.loads(pre_path.read_text(encoding="utf-8"))["outcome"] == "blocked"

    assert (
        _run_plugin(
            source,
            tmp_path,
            'plugin.hooks.afterTool({toolCall:{toolCallId:"3",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"safe",isError:false}})',
        )
        is None
    )
    post_path = context.guard_home / "managed" / "cline" / "proofs" / "plugin-posttool.json"
    assert json.loads(post_path.read_text(encoding="utf-8"))["outcome"] == "unchanged"

    replaced = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"4",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false}})',
    )
    assert isinstance(replaced, dict) and replaced["result"]["isError"] is True
    assert json.loads(post_path.read_text(encoding="utf-8"))["outcome"] == "replaced"

    assert (
        _run_plugin(
            source,
            tmp_path,
            (
                'plugin.hooks.afterTool({toolCall:{toolCallId:"4b",toolName:"read_files"},'
                'input:{paths:["README.md"]},result:{output:"safe again",isError:false}})'
            ),
        )
        is None
    )
    assert json.loads(post_path.read_text(encoding="utf-8"))["outcome"] == "replaced"


def test_plugin_ready_requires_block_and_replacement_proofs(tmp_path: Path) -> None:
    context = _context(tmp_path)
    root = context.home_dir / ".cline" / "plugins" / "hol-guard"
    root.mkdir(parents=True)
    index = root / "index.js"
    source = "// HOL_GUARD_MANAGED_CLINE_PLUGIN_V1\nexport default {};\n"
    index.write_bytes(source.encode("utf-8"))
    package = root / "package.json"
    package.write_text('{"name":"hol-guard-cline-plugin"}\n', encoding="utf-8")
    state_path = context.guard_home / "managed" / "cline" / "plugin-state.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "transport": "plugin",
                "root": str(root),
                "index_path": str(index),
                "package_path": str(package),
                "index_sha256": sha256(source.encode()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    proof_root = context.guard_home / "managed" / "cline" / "proofs"
    proof_root.mkdir(parents=True)

    now = time.time()
    for name, outcome in (("loaded", "loaded"), ("pretool", "allowed"), ("posttool", "unchanged")):
        (proof_root / f"plugin-{name}.json").write_text(
            json.dumps({"source": "cline-plugin", "proof": name, "outcome": outcome, "timestamp": now}),
            encoding="utf-8",
        )
    state = cline_plugin_state(context)
    assert state["pretool_blocking_proven"] is False
    assert state["posttool_replacement_proven"] is False
    assert state["ready"] is False

    (proof_root / "plugin-pretool.json").write_text(
        json.dumps({"source": "cline-plugin", "proof": "pretool", "outcome": "blocked", "timestamp": now}),
        encoding="utf-8",
    )
    (proof_root / "plugin-posttool.json").write_text(
        json.dumps({"source": "cline-plugin", "proof": "posttool", "outcome": "replaced", "timestamp": now}),
        encoding="utf-8",
    )
    state = cline_plugin_state(context)
    assert state["pretool_blocking_proven"] is True
    assert state["posttool_replacement_proven"] is True
    assert state["ready"] is True


def test_real_guard_policy_requires_review_for_cline_env_read(tmp_path: Path) -> None:
    context = _context(tmp_path)
    secret_path = context.workspace_dir / ".env"
    secret_name = "OPENAI_" + "API_KEY"
    secret_value = "HOL_GUARD_CLINE_" + "TEST_ONLY"
    secret_path.write_text(f"{secret_name}={secret_value}\n", encoding="utf-8")
    payload = {
        "hookName": "PreToolUse",
        "hook_event_name": "PreToolUse",
        "tool_call": {
            "id": "cline-live-regression",
            "name": "read_files",
            "input": {"path": str(secret_path)},
        },
        "preToolUse": {
            "toolName": "read_files",
            "parameters": {"path": str(secret_path)},
        },
    }
    env = dict(os.environ)
    env["HOME"] = str(context.home_dir)
    env["HOL_GUARD_HOME"] = str(context.guard_home)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "cline",
            "--json",
        ],
        cwd=context.workspace_dir,
        env=env,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    response = json.loads(result.stdout)
    assert response["policy_action"] == "require-reapproval"
    assert response["artifact_id"].startswith("cline:project:file-read:")
    assert response["policy_composition"]["current_config_action"] == "require-reapproval"


def test_real_guard_policy_withholds_cline_credential_output(tmp_path: Path) -> None:
    context = _context(tmp_path)
    source_path = context.workspace_dir / "public.txt"
    credential = "AKIA" + ("A" * 16)
    source_path.write_text(f"{credential}\n", encoding="utf-8")
    command = f"cat {source_path}"
    payload = {
        "hookName": "PostToolUse",
        "hook_event_name": "PostToolUse",
        "tool_result": {
            "id": "cline-live-posttool-regression",
            "name": "run_commands",
            "input": {"commands": [command]},
            "output": credential,
        },
    }
    env = dict(os.environ)
    env["HOME"] = str(context.home_dir)
    env["HOL_GUARD_HOME"] = str(context.guard_home)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "hook",
            "--harness",
            "cline",
            "--json",
        ],
        cwd=context.workspace_dir,
        env=env,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    response = json.loads(result.stdout)
    assert response["policy_action"] == "require-reapproval"
    assert ":tool-output:" in response["artifact_id"]
    assert response["policy_composition"]["current_config_action"] == "require-reapproval"
    serialized = json.dumps(response)
    assert credential not in serialized


def test_cline_safe_verification_reports_live_plugin_readiness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    runtime = {
        "hosts": ["cli"],
        "cli_version": "3.0.51",
        "vscode_versions": [],
        "jetbrains_detected": False,
        "active_transport": "plugin",
        "native_hooks": {"installed": False, "ready": False},
        "plugin": {
            "installed": True,
            "integrity_ok": True,
            "pretool_blocking_proven": True,
            "posttool_replacement_proven": True,
            "ready": True,
        },
        "mcp": {"configured": False, "ready": True},
        "duplicate_managed_transports": False,
    }
    monkeypatch.setattr(ClineHarnessAdapter, "runtime_probe", lambda self, _context: runtime)

    payload = build_harness_verification("cline", context, surface="plugin")

    verification = payload["verification"]
    assert verification["runtime"] == runtime
    assert verification["active_transport"] == "plugin"
    assert verification["requested_transport"] == "plugin"
    assert verification["ready"] is True


def test_cline_safe_verification_does_not_trust_inactive_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    runtime = {
        "hosts": ["cli"],
        "cli_version": "3.0.51",
        "vscode_versions": [],
        "jetbrains_detected": False,
        "active_transport": "hooks",
        "native_hooks": {"installed": True, "ready": True},
        "plugin": {"installed": True, "integrity_ok": True, "ready": True},
        "mcp": {"configured": False, "ready": True},
        "duplicate_managed_transports": True,
    }
    monkeypatch.setattr(ClineHarnessAdapter, "runtime_probe", lambda self, _context: runtime)

    payload = build_harness_verification("cline", context, surface="plugin")

    verification = payload["verification"]
    assert verification["active_transport"] == "hooks"
    assert verification["requested_transport"] == "plugin"
    assert verification["ready"] is False
