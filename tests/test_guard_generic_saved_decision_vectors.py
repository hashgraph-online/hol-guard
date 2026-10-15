"""The generic hook ships the recorded saved-decision probe groups in one resident call.

The vectors were recorded from the former Python composition of the generic
hook's saved-decision probes. The Rust resident replays the same vectors in
``policy_lookup_groups_tests.rs``; here the request Python builds must carry the
recorded groups and portable workspace with the current action's reuse
request. Groups probing the current token leave its hash for the resident to
build from the approval-context inputs, and a legacy hash equal to that token is
left for the resident to drop. The resident answer is returned unchanged with
the token it built and its reuse verdict.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import store_portable_project_memory
from codex_plugin_scanner.guard.cli import commands_hook_native_generic
from codex_plugin_scanner.guard.runtime.approval_reuse import _decision_from_native_payload
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import PolicyLookupEvidence

_FIXTURE = (
    Path(__file__).parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "tests"
    / "fixtures"
    / "generic_saved_decision_vectors.json.gz"
)
_VECTORS = json.loads(gzip.decompress(_FIXTURE.read_bytes()))["vectors"]
_DEGRADED_TRUST = {"remembered_rules": "disabled_degraded", "trusted": False}
_REUSE = {
    "action": "review",
    "status": "not-applicable",
    "reason_code": "approval_reuse_no_saved_decision",
    "current_action": "review",
    "saved_action": None,
    "should_claim": False,
}


@pytest.mark.parametrize("vector", _VECTORS[::8], ids=lambda vector: vector["name"])
def test_generic_saved_decision_ships_recorded_groups(vector, monkeypatch, tmp_path):
    candidates = {group["candidate_artifact_ids"][0]: group["candidate_artifact_ids"][1:] for group in vector["groups"]}

    def memory_lookup_candidates(_harness: str, artifact_id: str, **_kwargs: Any) -> tuple[list[str], str | None]:
        rest = candidates[artifact_id]
        memory = rest[-1] if rest and rest[-1].endswith("#memory") else None
        return [item for item in rest if item != memory], memory

    evidence = PolicyLookupEvidence(
        now="2026-01-01T00:00:00Z",
        integrity_state={},
        degraded_trust_status=_DEGRADED_TRUST if vector["degraded"] else None,
    )
    requests: list[dict[str, object]] = []

    def send(_store: GuardStore, request: dict[str, object]) -> dict[str, Any]:
        requests.append(request)
        return {
            **vector["expected"],
            "reuse": _REUSE,
            "saved_present": True,
            "saved_artifact_hash": None,
            "current_token": vector["artifact_hash"],
        }

    monkeypatch.setattr(store_portable_project_memory, "memory_lookup_candidates", memory_lookup_candidates)
    monkeypatch.setattr(GuardStore, "policy_lookup_evidence", lambda _store, **_kwargs: evidence)
    monkeypatch.setattr(GuardStore, "send_policy_decision_lookup", send)
    monkeypatch.setattr(
        GuardStore, "_portable_project_workspace", staticmethod(lambda _ws: vector["portable_workspace"])
    )
    monkeypatch.setattr(commands_hook_native_generic, "_generic_hook_memory_command", lambda _payload: "echo")
    diagnosed: list[tuple[object, ...]] = []
    evaluated: list[tuple[object, ...]] = []

    def diagnostic(_store: GuardStore, *args: object) -> tuple[str, None]:
        diagnosed.append(args)
        return "approval_reuse_integrity_failure", None

    def evaluate(*args: object, **kwargs: object) -> object:
        evaluated.append((*args, kwargs))
        return _decision_from_native_payload(_REUSE)

    monkeypatch.setattr(GuardStore, "approval_reuse_diagnostic", diagnostic)
    monkeypatch.setattr(commands_hook_native_generic, "evaluate_approval_reuse", evaluate)
    tokens: list[tuple[str, dict[str, object]]] = []

    def token(kind: str, inputs: dict[str, object]) -> str:
        tokens.append((kind, inputs))
        return vector["artifact_hash"]

    monkeypatch.setattr(commands_hook_native_generic, "native_hook_approval_context_token", token)
    inputs: dict[str, object] = {"artifact": {"artifact_id": vector["artifact_id"]}}

    result = commands_hook_native_generic._generic_hook_saved_decision(
        approval_context_inputs=inputs,
        artifact_id=vector["artifact_id"],
        artifact_name="Bash",
        current_action="review",
        harness="claude-code",
        legacy_artifact_hash=vector["legacy_artifact_hash"],
        payload={"tool_name": "Bash", "tool_input": {"command": "echo"}},
        publisher=None,
        runtime_workspace=Path(vector["workspace"]),
        store=GuardStore(tmp_path / "home"),
    )

    current_token, decision, ignored, reuse, saved_present = result
    assert current_token == vector["artifact_hash"]
    if vector["degraded"]:
        assert requests == []
        assert tokens == [("generic_hook_approval_context", inputs)]
        # A degraded home still explains the miss and fails closed on saved rows.
        assert (decision, ignored, saved_present) == (None, None, True)
        assert diagnosed == [("claude-code", vector["artifact_id"], vector["artifact_hash"], vector["workspace"], None)]
        assert evaluated == [
            (
                "review",
                "allow",
                {"saved_decision_present": True, "validation_reason": "approval_reuse_integrity_failure"},
            )
        ]
        assert reuse == _decision_from_native_payload(_REUSE)
        return
    assert diagnosed == [] and evaluated == [] and tokens == []
    [request] = requests
    assert request["consume_one_shot"] is False
    assert request["workspace"] == vector["workspace"]
    assert (request["artifact_id"], request["artifact_hash"]) == (vector["artifact_id"], None)
    groups = [
        {**group, "artifact_hash": None} if group["artifact_hash"] == vector["artifact_hash"] else group
        for group in vector["groups"]
    ]
    if vector["legacy_artifact_hash"] == vector["artifact_hash"]:
        groups.append({**vector["groups"][0], "artifact_hash": vector["legacy_artifact_hash"]})
    assert request["probe_groups"] == {
        "portable_workspace": vector["portable_workspace"],
        "groups": groups,
        "reuse": {"current_action": "review", "approval_context_inputs": inputs},
    }
    assert (decision, ignored) == (vector["expected"]["decision"], vector["expected"]["ignored_local_integrity"])
    assert reuse == _decision_from_native_payload(_REUSE)
    assert saved_present is True
