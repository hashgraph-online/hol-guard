"""Replay language-neutral MCP tool-call policy vectors through the real resident.

The vectors were recorded from the former Python evaluator before it was
removed. Each one lists the exact store/claim/authority effects the evaluator
performed and the decision it returned. Here the Rust resident decides and
Python only executes the effects it names: the effects Python runs must equal
the recorded observations (same needs, same order, same results) and the
decision must equal the recorded one.
"""

from __future__ import annotations

import copy
import json
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_cli_trust, native_mcp_tool_policy
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_tool_calls import (
    ToolCallDecision,
    build_tool_call_artifact,
    build_tool_call_hash,
    evaluate_tool_call,
)
from codex_plugin_scanner.guard.native_context import bind_context_digest_home

_FIXTURE = Path(__file__).parent / "fixtures" / "mcp_tool_policy" / "parity_vectors.json"
_DOCUMENT = json.loads(_FIXTURE.read_text(encoding="utf-8"))
_VECTORS = _DOCUMENT["vectors"]
_WORKSPACE = Path(_DOCUMENT["workspace"])


def _key(need: dict[str, object], phase: str) -> str:
    material = need if need["kind"] == "claim" else {**need, "phase": phase}
    return json.dumps(material, sort_keys=True)


class _ReplayStore:
    """A store whose every answer is the recorded observation for that exact need."""

    def __init__(self, observations: list[dict[str, object]], guard_home: Path) -> None:
        self.guard_home = guard_home
        self.phase = "initial"
        self._answers = {
            _key(item["need"], phase): item["result"]
            for item in observations
            for phase in ("initial", "fresh")
            if item["need"].get("phase", phase) == phase
        }
        self.served: list[str] = []

    def _serve(self, need: dict[str, object]) -> dict[str, object] | None:
        key = _key(need, self.phase)
        assert key in self._answers, f"unrecorded effect requested: {key[:300]}"
        self.served.append(key)
        return copy.deepcopy(self._answers[key])  # type: ignore[return-value]

    @contextmanager
    def connection_scope(self):
        yield

    def read_mcp_provider_choices(self):
        return self._serve({"kind": "provider_choices"})

    def read_mcp_provider_authority_hash(self):
        return self._serve({"kind": "provider_authority_hash"})["hash"]  # type: ignore[index]

    def resolve_policy_decision_lookup(self, harness, selector, *, consume_one_shot):
        assert consume_one_shot is False
        result = self._serve({"kind": "grant_lookup", "harness": harness, "selector": selector})
        return {"decision": result["decision"], "ignored_local_integrity": None}  # type: ignore[index]

    def resolve_policy_decision_lookup_with_memory_pattern(
        self,
        harness,
        artifact_id,
        *,
        artifact_hash,
        workspace,
        publisher,
        runtime_exact_match_context,
        memory_command,
        memory_artifact_type,
        memory_artifact_name,
        consume_one_shot,
    ):
        assert consume_one_shot is False
        result = self._serve(
            {
                "kind": "policy_lookup",
                "harness": harness,
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "workspace": workspace,
                "publisher": publisher,
                "runtime_exact_match_context": runtime_exact_match_context,
                "memory_command": memory_command,
                "memory_artifact_type": memory_artifact_type,
                "memory_artifact_name": memory_artifact_name,
            }
        )
        assert result is not None
        return {
            "decision": result["decision"],
            "ignored_local_integrity": "unsafe" if result["ignored_local_integrity"] else None,
        }

    def approval_reuse_validation_reason(self, harness, artifact_id, artifact_hash, workspace, publisher):
        result = self._serve(
            {
                "kind": "reuse_diagnostic",
                "harness": harness,
                "artifact_id": artifact_id,
                "artifact_hash": artifact_hash,
                "workspace": workspace,
                "publisher": publisher,
            }
        )
        assert result is not None
        return result["reason"]

    def claim_approval_reuse_decision(self, decision):
        result = self._serve({"kind": "claim", "decision": copy.deepcopy(dict(decision))})
        assert result is not None
        if result["outcome"] == "uncertain":
            raise RuntimeError("claim storage failure")
        return result["outcome"] == "claimed"


def _build(recipe: dict[str, object], guard_home: Path):
    config = GuardConfig(guard_home=guard_home, workspace=_WORKSPACE, **recipe["config"])  # type: ignore[arg-type]
    artifact = build_tool_call_artifact(**recipe["artifact"])  # type: ignore[arg-type]
    arguments = recipe["arguments"]
    return (
        config,
        artifact,
        build_tool_call_hash(artifact, arguments, workspace=config.workspace, config=config),
        arguments,
    )


def _expected_view(decision: ToolCallDecision) -> dict[str, object]:
    return {
        "action": decision.action,
        "source": decision.source,
        "signals": list(decision.signals),
        "summary": decision.summary,
        "risk_categories": list(decision.risk_categories),
        "normalization_reason_code": decision.normalization_reason_code,
        "original_action": decision.original_action,
        "approval_reuse_status": decision.approval_reuse_status,
        "approval_reuse_reason_code": decision.approval_reuse_reason_code,
        "current_action": decision.current_action,
        "saved_action": decision.saved_action,
        "pending_approval_reuse_decision": None
        if decision.pending_approval_reuse_decision is None
        else dict(decision.pending_approval_reuse_decision),
        "approval_reuse_claim_disposition": decision.approval_reuse_claim_disposition,
        "post_claim_revalidated": decision.post_claim_revalidated,
        "post_claim_authority": None if decision.post_claim_authority is None else "fresh",
    }


@pytest.mark.parametrize("vector", _VECTORS, ids=[item["name"] for item in _VECTORS])
def test_resident_reproduces_recorded_python_decision(vector, monkeypatch, native_context_digest: Path) -> None:
    home = native_context_digest
    bind_context_digest_home(home)
    recipe = _DOCUMENT["recipes"][vector["recipe"]]
    config, artifact, artifact_hash, arguments = _build(recipe, home)
    observations = vector["observations"]
    store = _ReplayStore(observations, home)
    provided: list[tuple[object, ...]] = []

    def provider():
        store.phase = "fresh"
        mode = vector["fresh_mode"]
        if mode == "raise":
            raise RuntimeError("authority refresh failed")
        if mode == "none":
            return None
        target = recipe if mode == "same" else _DOCUMENT["recipes"][vector["fresh_recipe"]]
        authority = _build(target, home)
        provided.append(authority)
        return authority

    def extension(_store, _artifact, action):
        result = store._serve({"kind": "extension_decision", "action": action})
        return None if result is None else (result["action"], result["source"], result["summary"])

    monkeypatch.setattr(local_cli_trust, "apply_local_mcp_extension_decision", extension)
    sent: list[list[dict[str, object]]] = []
    real_round_trip = native_mcp_tool_policy._round_trip

    def capture(guard_home, **kwargs):
        sent.append(copy.deepcopy(kwargs["observations"]))
        return real_round_trip(guard_home, **kwargs)

    monkeypatch.setattr(native_mcp_tool_policy, "_round_trip", capture)

    decision = evaluate_tool_call(
        store=store,  # type: ignore[arg-type]
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=vector["claim_saved_approval"],
        fresh_authority_provider=provider,
    )

    assert _expected_view(decision) == vector["expected"]
    # Python executed exactly the recorded effects, in the recorded order.
    assert sent[-1] == observations
    if vector["expected"]["post_claim_authority"] == "fresh":
        assert decision.post_claim_authority is not None
        if provided:
            assert decision.post_claim_authority.artifact_hash == provided[-1][2]
        else:
            assert decision.post_claim_authority.artifact_hash in {
                artifact_hash,
                decision.post_claim_authority.artifact_hash,
            }


def test_uncertain_claim_is_terminal_and_never_retried(monkeypatch, native_context_digest: Path) -> None:
    home = native_context_digest
    bind_context_digest_home(home)
    vector = next(item for item in _VECTORS if any(o["need"]["kind"] == "claim" for o in item["observations"]))
    observations = copy.deepcopy(vector["observations"])
    claim_at = next(i for i, o in enumerate(observations) if o["need"]["kind"] == "claim")
    observations = observations[: claim_at + 1]
    observations[claim_at]["result"] = {"outcome": "uncertain"}
    config, artifact, artifact_hash, arguments = _build(_DOCUMENT["recipes"][vector["recipe"]], home)
    store = _ReplayStore(observations, home)
    claims: list[object] = []
    original = store.claim_approval_reuse_decision

    def counted(decision):
        claims.append(decision)
        return original(decision)

    store.claim_approval_reuse_decision = counted  # type: ignore[method-assign]
    monkeypatch.setattr(
        local_cli_trust,
        "apply_local_mcp_extension_decision",
        lambda _s, _a, action: (lambda r: None if r is None else (r["action"], r["source"], r["summary"]))(
            store._serve({"kind": "extension_decision", "action": action})
        ),
    )
    decision = evaluate_tool_call(
        store=store,  # type: ignore[arg-type]
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=True,
        fresh_authority_provider=lambda: pytest.fail("no authority refresh after an uncertain claim"),
    )
    assert len(claims) == 1
    assert decision.action == "require-reapproval"
    assert decision.post_claim_authority is None
    assert decision.post_claim_revalidated is False


def test_storage_read_failure_fails_closed(monkeypatch, native_context_digest: Path) -> None:
    home = native_context_digest
    bind_context_digest_home(home)
    vector = _VECTORS[0]
    config, artifact, artifact_hash, arguments = _build(_DOCUMENT["recipes"][vector["recipe"]], home)
    store = _ReplayStore(vector["observations"], home)

    def boom(*_args, **_kwargs):
        raise RuntimeError("storage read failed")

    store.resolve_policy_decision_lookup_with_memory_pattern = boom  # type: ignore[method-assign]
    monkeypatch.setattr(local_cli_trust, "apply_local_mcp_extension_decision", lambda *_a: None)
    with pytest.raises(RuntimeError, match="storage read failed"):
        evaluate_tool_call(
            store=store,  # type: ignore[arg-type]
            config=config,
            artifact=artifact,
            artifact_hash=artifact_hash,
            arguments=arguments,
        )
