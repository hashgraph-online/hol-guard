"""Composed enrolled Codex plans restore every prepared file generation."""

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_harness_install_ops as harness_install_ops
from codex_plugin_scanner.guard.codex_harness_client import codex_paths
from codex_plugin_scanner.guard.codex_hook_integrity import CodexHookIntegrityError
from tests import harness_ops_support as harness_support
from tests.codex_toml_support import parse_toml_object

from .test_codex_publication_preparation import _context, _tree
from .test_frozen_codex_runtime import frozen_codex_contract  # noqa: F401 -- shared pytest fixture
from .test_runtime_transition import begin, transition  # noqa: F401 -- shared pytest fixture

SHELL_GUARD_BEGIN = "# >>> HOL Guard Codex shell guard >>>"
SHELL_GUARD_END = "# <<< HOL Guard Codex shell guard <<<"


def _sources(tmp_path, monkeypatch):
    context = replace(_context(tmp_path, monkeypatch), workspace_dir=tmp_path / "workspace")
    harness_support.install("codex", context)
    global_config = codex_paths(context).config
    global_config.write_text(
        global_config.read_text() + '\n[mcp_servers.fixture]\ncommand="node"\nargs=["fixture.js"]\n'
    )
    workspace_config = context.workspace_dir / ".codex/config.toml"
    workspace_config.parent.mkdir(parents=True, exist_ok=True)
    workspace_config.write_text('model="workspace"\n[mcp_servers.project]\ncommand="node"\nargs=["project.js"]\n')
    workspace_config.chmod(0o644)
    for config in (global_config, workspace_config):
        config.with_name("hooks.json").write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {"matcher": "Bash", "hooks": [{"type": "command", "command": "python user_hook.py"}]},
                        ]
                    }
                }
            )
        )
    context.home_dir.joinpath(".zshenv").write_bytes(
        b"\xffKEEP\n\n" + SHELL_GUARD_BEGIN.encode() + b"\nlegacy\n" + SHELL_GUARD_END.encode() + b"\nAFTER\xfe\n"
    )
    guard = context.guard_home / "managed/codex/codex-zshenv-guard.zsh"
    guard.write_bytes(b"legacy guard script")
    guard.chmod(0o700)
    return context, global_config, workspace_config


def test_composed_preparation_is_read_only_and_captures_complete_native_files(tmp_path, monkeypatch):
    context, global_config, workspace_config = _sources(tmp_path, monkeypatch)
    before = _tree(tmp_path)
    prepared = harness_install_ops.prepare_install("codex", context)
    assert _tree(tmp_path) == before
    changes = {change.path: change for change in prepared.files}
    assert len(changes) == len(prepared.files)
    for config in (global_config, workspace_config):
        assert changes[config.with_name("hooks.json")].after is None
        assert changes[config.with_name("hooks.json")].before is not None
        payload = parse_toml_object(changes[config].after, path=config, label="fixture")
        assert any(group["hooks"][0]["command"] == "python user_hook.py" for group in payload["hooks"]["PreToolUse"])
    global_payload = parse_toml_object(changes[global_config].after, path=global_config, label="fixture")
    workspace_payload = parse_toml_object(changes[workspace_config].after, path=workspace_config, label="fixture")
    assert "codex-mcp-proxy" in global_payload["mcp_servers"]["fixture"]["args"]
    assert "codex-mcp-proxy" in global_payload["mcp_servers"]["project"]["args"]
    assert "project" not in workspace_payload.get("mcp_servers", {})
    assert changes[context.home_dir / ".zshenv"].after == b"\xffKEEP\nAFTER\xfe\n"
    assert changes[context.guard_home / "managed/codex/codex-zshenv-guard.zsh"].after is None
    assert context.guard_home / "bin/guard-codex" in changes
    assert context.guard_home / "bin/guard-codex.cmd" in changes
    assert any(change.expected_digest is not None for change in prepared.files)
    signed = json.loads(changes[Path(prepared.manifest["managed_hook_manifest_path"])].after)
    interpreter = signed["interpreter"]
    invocations = [change.invocation_identity for change in prepared.files if change.invocation_identity is not None]
    assert invocations == [
        {
            "path": interpreter["invocation_path"],
            "mode": interpreter["invocation_mode"],
            "owner_uid": interpreter["invocation_owner_uid"],
            "link_target": interpreter["link_target"],
        }
    ]


def test_composed_signed_inverse_restores_all_files_and_modes(
    transition,
    tmp_path,
    monkeypatch,
):
    runtime, plan, _bindings, _pointer = transition
    context, _global_config, _workspace_config = _sources(tmp_path, monkeypatch)
    prepared = harness_install_ops.prepare_install("codex", context)
    plan = replace(plan, files=(*plan.files, *prepared.files))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    runtime.restore_files(plan.operation_id, first_cause="fixture candidate bootstrap failed")
    for change in prepared.files:
        if change.expected_digest is not None:
            continue
        if change.before is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.before
            assert change.path.stat().st_mode & 0o777 == change.before_mode


def test_preparation_refuses_missing_authority_without_enrollment(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    before = _tree(tmp_path)
    with pytest.raises(CodexHookIntegrityError):
        harness_install_ops.prepare_install("codex", context)
    assert _tree(tmp_path) == before


@pytest.mark.usefixtures("frozen_codex_contract")
def test_frozen_preparation_pins_shared_executable_once_with_invocation(tmp_path, monkeypatch):
    executable = tmp_path / "frozen-core"
    executable.write_bytes(b"isolated frozen executable identity")
    executable.chmod(0o700)
    monkeypatch.setattr(sys, "executable", str(executable))
    context = _context(tmp_path, monkeypatch)
    harness_support.install("codex", context)
    before = _tree(tmp_path)
    prepared = harness_install_ops.prepare_install("codex", context)
    assert _tree(tmp_path) == before
    dependencies = [change for change in prepared.files if change.path == executable]
    assert len(dependencies) == 1
    assert dependencies[0].expected_digest is not None
    assert dependencies[0].invocation_identity["path"] == str(executable)


def test_prepared_file_generations_match_ordinary_install(tmp_path, monkeypatch):
    context, _global_config, _workspace_config = _sources(tmp_path, monkeypatch)
    prepared = harness_install_ops.prepare_install("codex", context)
    installed = harness_support.install("codex", context)
    for change in prepared.files:
        if change.expected_digest is not None:
            continue
        if str(change.path) == prepared.manifest["managed_hook_manifest_path"]:
            actual = json.loads(change.path.read_bytes())
            expected = json.loads(change.after)
            for field in (
                "events",
                "installation_id",
                "interpreter",
                "packaged_files",
                "context",
                "retained_bridge_generations",
                "compatible_bridge_argv_sha256",
            ):
                assert actual[field] == expected[field]
        elif change.path.name.endswith(".authority-receipt.json"):
            import base64

            actual_receipt = json.loads(change.path.read_bytes())
            expected_receipt = json.loads(change.after)
            for field in ("schema", "guard_home", "config_path", "installation_id", "config_sha256"):
                assert actual_receipt[field] == expected_receipt[field]
            actual_manifest = json.loads(base64.b64decode(actual_receipt["manifest"], validate=True))
            expected_manifest = json.loads(base64.b64decode(expected_receipt["manifest"], validate=True))
            for field in (
                "events",
                "installation_id",
                "interpreter",
                "packaged_files",
                "context",
                "retained_bridge_generations",
                "compatible_bridge_argv_sha256",
            ):
                assert actual_manifest[field] == expected_manifest[field]
            assert change.path.stat().st_mode & 0o777 == change.after_mode
        elif change.after is None:
            assert not change.path.exists()
        else:
            assert change.path.read_bytes() == change.after
            assert change.path.stat().st_mode & 0o777 == change.after_mode
    assert installed["managed_servers"] == prepared.manifest["managed_servers"]
    before = _tree(tmp_path)
    repeated = harness_install_ops.prepare_install("codex", context)
    assert _tree(tmp_path) == before
    assert len({change.path for change in repeated.files}) == len(repeated.files)


def test_foreign_source_before_the_plan_is_never_overwritten(tmp_path, monkeypatch):
    context, _global_config, workspace_config = _sources(tmp_path, monkeypatch)
    # The runtime reads the sources itself as it plans, and a plan publishes nothing.
    workspace_config.write_text('model="foreign"\n')
    harness_install_ops.prepare_install("codex", context)
    assert workspace_config.read_text() == 'model="foreign"\n'
    assert workspace_config.with_name("hooks.json").exists()
    assert context.home_dir.joinpath(".zshenv").read_bytes().startswith(b"\xffKEEP")
