"""The resident reads saved policy for an MCP tools/call exactly as the Python lookup did.

One call runs twice against the same store: once with the evidence shipped so
the resident reads the saved policy itself, once forced through the
``policy_lookup`` effect that still serves the fresh-authority pass. The
decisions must be identical, and the in-process read must need no round trip
for the lookup.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_execution, native_mcp_tool_policy
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact, build_tool_call_hash
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_runtime_mcp_saved_blocks import _child_command, _context

pytestmark = [pytest.mark.usefixtures("bundle_first_cloud"), pytest.mark.usefixtures("package_intent_native")]

_ARGUMENTS: dict[str, object] = {"target": ".env"}
_ROW_SCENARIOS = ("exact_block", "exact_allow", "artifact_review")
_SCENARIOS = ("empty", "exact_block", "exact_allow", "artifact_review", "other_workspace_row")


def _subject(tmp_path: Path, store: GuardStore, context, scenario: str):
    config = GuardConfig(mode="enforce", guard_home=context.guard_home, workspace=context.workspace_dir)
    proxy = CodexMcpGuardProxy(
        server_name="workspace-tools",
        command=_child_command(tmp_path / "marker.json"),
        context=context,
        store=store,
        config=config,
        source_scope="project",
        config_path=str(context.workspace_dir / ".codex" / "config.toml"),
    )
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="workspace-tools",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path=proxy.config_path,
        transport="stdio",
        server_fingerprint={"command": proxy.command, "transport": "stdio"},
        server_identity=proxy.server_identity,
        tool_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        tool_description="Dangerous delete",
    )
    digest = build_tool_call_hash(artifact, _ARGUMENTS, workspace=context.workspace_dir, config=config)
    rows = {
        "exact_block": ("artifact", "block", digest, None),
        "exact_allow": ("artifact", "allow", digest, None),
        "artifact_review": ("artifact", "review", None, None),
        "other_workspace_row": ("workspace", "block", None, str(context.workspace_dir / "elsewhere")),
    }
    if scenario in rows:
        scope, action, artifact_hash, workspace = rows[scenario]
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope=scope,
                action=action,
                artifact_id=artifact.artifact_id if scope == "artifact" else None,
                artifact_hash=artifact_hash,
                workspace=workspace,
                reason="operator decision",
                source="approval-gate",
            ),
            "2026-07-17T00:00:00Z",
        )
    return config, artifact, digest


def _evaluate(store, config, artifact, digest):
    return native_mcp_tool_policy.native_evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=_ARGUMENTS,
        claim_saved_approval=False,
        fresh_authority_provider=None,
    )


@pytest.mark.parametrize("scenario", _SCENARIOS)
def test_in_process_saved_policy_read_equals_the_policy_lookup_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_mcp_probe,
    scenario: str,
) -> None:
    context = _context(tmp_path)
    native_mcp_probe(context.guard_home)
    store = GuardStore(context.guard_home)
    config, artifact, digest = _subject(tmp_path, store, context, scenario)
    operations: collections.Counter[str] = collections.Counter()
    real = native_execution.native_resident_client_request

    def spy(**kwargs):
        envelope = json.loads(kwargs["payload"])
        request = envelope["request"]
        needs = [item["need"]["kind"] for item in request.get("observations", [])]
        operations[envelope["operation"] + ":" + ",".join(needs)] += 1
        return real(**kwargs)

    monkeypatch.setattr(native_execution, "native_resident_client_request", spy)

    inprocess = _evaluate(store, config, artifact, digest)
    shipped = collections.Counter(operations)
    operations.clear()
    monkeypatch.setattr(native_mcp_tool_policy, "_lookup_input", lambda *_args, **_kwargs: None)
    effect = _evaluate(store, config, artifact, digest)

    assert dict(inprocess.payload) == dict(effect.payload), scenario
    # A miss is read in-process. A saved row can be consumed by a claim, so it is
    # pinned through the effect: every round replays the pass and must see one row.
    assert any("policy_lookup" in key for key in shipped) == (scenario in _ROW_SCENARIOS), dict(shipped)
    assert any("policy_lookup" in key for key in operations), dict(operations)


def test_a_store_without_the_lookup_input_falls_back_to_the_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_mcp_probe,
) -> None:
    context = _context(tmp_path)
    native_mcp_probe(context.guard_home)
    store = GuardStore(context.guard_home)
    config, artifact, digest = _subject(tmp_path, store, context, "exact_block")

    def broken(*_args, **_kwargs):
        raise ValueError("evidence unavailable")

    monkeypatch.setattr(store, "mcp_policy_lookup_input", broken)
    result = _evaluate(store, config, artifact, digest)
    assert result.payload["action"] == "block"
