"""Independent finite callback witness; the child only records JSON."""

import json
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, runtime_mcp
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore

from .test_guard_runtime_mcp_saved_blocks import _child_command, _context, _messages, _package_artifact


@pytest.mark.usefixtures("bundle_first_cloud")
@pytest.mark.parametrize("mutation_stage", ["unchanged", "drain", "fresh_tool_grant"])
def test_package_drain_keeps_selected_artifact_authority(tmp_path, monkeypatch, mutation_stage):
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        security_level="custom",
        default_action="warn",
        risk_actions={"mcp_dangerous_tool": "warn", "package_script": "warn"},
    )
    marker = tmp_path / "wire.json"
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(marker),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex/config.toml"),
        current_config_provider=lambda: config,
    )
    artifact = _package_artifact(context=context, harness="codex", config_path=proxy.config_path)
    evaluation = replace(
        evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=context.workspace_dir),
        decision="allow",
        policy_action="allow",
    )
    selected = []
    evaluations = []
    mutations = []
    original_package = proxy._package_request_artifact
    original_drain = proxy._drain_and_validate_catalog_authority
    original_grant = proxy.store.read_local_mcp_grant

    def package(**kwargs):
        result = original_package(**kwargs)
        if result is not None:
            selected.append(result)
        return result

    def evaluate(**kwargs):
        current = kwargs["artifact"]
        evaluations.append({"private_changed": current.runtime_private_metadata.get("changed_after_drain", False)})
        return evaluation

    def drain(**kwargs):
        result = original_drain(**kwargs)
        if mutation_stage == "drain" and selected and not mutations:
            selected[0].runtime_private_metadata["changed_after_drain"] = True
            mutations.append(True)
        return result

    def grant(*args, **kwargs):
        result = original_grant(*args, **kwargs)
        if mutation_stage == "fresh_tool_grant" and selected and not mutations:
            selected[0].runtime_private_metadata["changed_after_drain"] = True
            mutations.append(True)
        return result

    monkeypatch.setattr(proxy.store, "read_local_mcp_grant", grant)
    monkeypatch.setattr(proxy, "_package_request_artifact", package)
    monkeypatch.setattr(runtime_mcp, "evaluate_package_request_artifact", evaluate)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    messages = _messages(
        tool_name="run_terminal_command", arguments={"command": "npm install minimist@1.2.8"}, elicitation=False
    )
    result = proxy.run_session(messages)
    (tmp_path / "witness.json").write_text(
        json.dumps(
            {
                "mutation_stage": mutation_stage,
                "evaluations": evaluations,
                "mutations": mutations,
                "selected_artifacts": len(selected),
                "child_received": marker.exists(),
                "wire": json.loads(marker.read_text()) if marker.exists() else None,
                "last_event": result["events"][-1],
                "scanner_stub": "fixed fixture allow; no scanner or performance credit",
            },
            indent=2,
        )
        + "\n"
    )
    if mutation_stage != "unchanged":
        assert mutations == [True]
        assert evaluations == [{"private_changed": False}], result["events"][-1]
        assert not marker.exists()
        assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"
    else:
        assert evaluations == [{"private_changed": False}, {"private_changed": False}]
        assert json.loads(marker.read_text()) == messages[-1]["params"]
        assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"
