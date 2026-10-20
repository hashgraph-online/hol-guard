"""The generic hook ships the recorded saved-decision probe groups in one resident call.

The vectors were recorded from the former Python composition of the generic
hook's saved-decision probes. The Rust resident replays the same vectors in
``policy_lookup_groups_tests.rs``; here the request Python builds must carry the
recorded groups' direct ids with the remembered-decision inputs the resident
expands them from, and the portable workspace with the current action's reuse
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

from codex_plugin_scanner.guard.cli import commands_hook_native_generic
from codex_plugin_scanner.guard.runtime.approval_reuse import _decision_from_native_payload
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import POLICY_LOOKUP_MEMORY_FEATURE, PolicyLookupEvidence

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
    evidence = PolicyLookupEvidence(
        now="2026-01-01T00:00:00Z",
        integrity_state={},
        degraded_trust_status=_DEGRADED_TRUST if vector["degraded"] else None,
    )
    requests: list[dict[str, object]] = []

    def send(_store: GuardStore, request: dict[str, object], *, required_feature: str = "") -> dict[str, Any]:
        requests.append(request)
        assert required_feature == POLICY_LOOKUP_MEMORY_FEATURE
        return {
            **vector["expected"],
            "reuse": _REUSE,
            "saved_present": True,
            "saved_artifact_hash": None,
            "current_token": vector["artifact_hash"],
        }

    monkeypatch.setattr(GuardStore, "policy_lookup_evidence", lambda _store, **_kwargs: evidence)
    monkeypatch.setattr(GuardStore, "send_policy_decision_lookup", send)
    monkeypatch.setattr(
        GuardStore, "_portable_project_workspace", staticmethod(lambda _ws: vector["portable_workspace"])
    )
    diagnosed: list[tuple[object, ...]] = []
    evaluated: list[tuple[object, ...]] = []

    def diagnostic(_store: GuardStore, *args: object, **kwargs: object) -> tuple[str, None, None]:
        diagnosed.append((*args, kwargs))
        # The resident could not answer, so it composed no reuse decision.
        return "approval_reuse_integrity_failure", None, None

    def evaluate(*args: object, **kwargs: object) -> object:
        evaluated.append((*args, kwargs))
        return _decision_from_native_payload(_REUSE)

    monkeypatch.setattr(GuardStore, "approval_reuse_miss", diagnostic)
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
        tool_command="echo",
    )

    current_token, decision, ignored, reuse, saved_present = result
    assert current_token == vector["artifact_hash"]
    if vector["degraded"]:
        assert requests == []
        assert tokens == [("generic_hook_approval_context", inputs)]
        # A degraded home still explains the miss and fails closed on saved rows.
        assert (decision, ignored, saved_present) == (None, None, True)
        assert diagnosed == [
            (
                "claude-code",
                vector["artifact_id"],
                vector["artifact_hash"],
                vector["workspace"],
                None,
                {"current_action": "review"},
            )
        ]
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
    # The resident appends each direct id's exact-command and memory candidates.
    groups = [
        {
            "artifact_hash": None if group["artifact_hash"] == vector["artifact_hash"] else group["artifact_hash"],
            "candidate_artifact_ids": group["candidate_artifact_ids"][:1],
        }
        for group in vector["groups"]
    ]
    if vector["legacy_artifact_hash"] == vector["artifact_hash"]:
        groups.append({**groups[0], "artifact_hash": vector["legacy_artifact_hash"]})
    assert request["probe_groups"] == {
        "portable_workspace": vector["portable_workspace"],
        "groups": groups,
        "reuse": {"current_action": "review", "approval_context_inputs": inputs},
        "memory": {
            "command": "echo",
            "artifact_type": "unknown-artifact",
            "artifact_name": "Bash",
            "harness": "claude-code",
        },
    }
    assert (decision, ignored) == (vector["expected"]["decision"], vector["expected"]["ignored_local_integrity"])
    assert reuse == _decision_from_native_payload(_REUSE)
    assert saved_present is True


def test_a_runtime_without_the_expansion_capability_is_never_sent_unexpanded_groups(monkeypatch, tmp_path):
    """The lookup capability alone does not qualify a runtime for this request.

    The groups carry only their direct id now, so a runtime that cannot expand
    them would answer a narrower question than the hook asked — and its
    probe-groups contract denies unknown fields, so the ``memory`` inputs it
    would have to expand from are what it rejects. Gating on the expansion
    capability keeps the request from being sent at all, and names the missing
    capability instead of a serde failure inside the answer.
    """

    from codex_plugin_scanner.guard import store_policy

    requested: list[str] = []

    def resident_request(*, required_feature: str, **_kwargs: object) -> dict[str, object] | None:
        requested.append(required_feature)
        # A runtime from before the expansion advertises the lookup and no more.
        return None

    monkeypatch.setattr(store_policy, "_resident_request", resident_request)
    monkeypatch.setattr(
        GuardStore,
        "policy_lookup_evidence",
        lambda _store, **_kwargs: PolicyLookupEvidence(
            now="2026-01-01T00:00:00Z", integrity_state={}, degraded_trust_status=None
        ),
    )
    monkeypatch.setattr(GuardStore, "_portable_project_workspace", staticmethod(lambda _workspace: None))

    with pytest.raises(ValueError, match="native_policy_decision_lookup_unavailable"):
        GuardStore(tmp_path / "home").peek_saved_decision_groups(
            "claude-code",
            [("artifact", None)],
            workspace=None,
            publisher=None,
            runtime_exact_match_context=None,
            memory_command="echo",
            memory_artifact_type="unknown-artifact",
            memory_artifact_name="Bash",
            current_action="review",
            approval_context_inputs={},
        )
    assert requested == [POLICY_LOOKUP_MEMORY_FEATURE]


def test_a_diagnosed_miss_carries_the_residents_own_reuse_decision(monkeypatch, tmp_path):
    """The miss path never names a saved action for the resident.

    A near match that could not authorize the request is evidence, not a
    grant. The resident composes what the miss means for reuse in the same
    call that diagnoses it, so nothing here invents an ``allow`` to compose
    against and no second round trip decides what the first one already knew.
    """

    composed = {
        **_REUSE,
        "status": "rejected",
        "reason_code": "approval_reuse_content_changed",
        "saved_action": "allow",
        "saved_artifact_hash_is_context_token": True,
    }
    asked: list[dict[str, object]] = []

    def miss(_store: GuardStore, *args: object, **kwargs: object) -> tuple[str, str, dict[str, object]]:
        asked.append({"args": args, "kwargs": kwargs})
        return "approval_reuse_content_changed", "guard-approval-context:v1:x", composed

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the resident already composed the miss")

    monkeypatch.setattr(GuardStore, "peek_saved_decision_groups", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(GuardStore, "approval_reuse_miss", miss)
    monkeypatch.setattr(commands_hook_native_generic, "evaluate_approval_reuse", never)
    monkeypatch.setattr(commands_hook_native_generic, "with_saved_artifact_hash_provenance", never)
    monkeypatch.setattr(
        commands_hook_native_generic,
        "native_hook_approval_context_token",
        lambda _kind, _inputs: "guard-approval-context:v1:current",
    )

    current_token, decision, ignored, reuse, saved_present = commands_hook_native_generic._generic_hook_saved_decision(
        approval_context_inputs={"artifact": {"artifact_id": "artifact"}},
        artifact_id="artifact",
        artifact_name="Bash",
        current_action="review",
        harness="claude-code",
        legacy_artifact_hash=None,
        payload={"tool_name": "Bash", "tool_input": {"command": "echo"}},
        publisher=None,
        runtime_workspace=Path("/workspace/a"),
        store=GuardStore(tmp_path / "home"),
        tool_command="echo",
    )

    assert (current_token, decision, ignored, saved_present) == (
        "guard-approval-context:v1:current",
        None,
        None,
        True,
    )
    assert reuse == _decision_from_native_payload(composed)
    # The recomputed action travels with the diagnosis, in one call.
    assert [entry["kwargs"] for entry in asked] == [{"current_action": "review"}]


@pytest.mark.parametrize("supports_reuse", [False, True])
def test_the_miss_names_the_current_action_only_to_a_resident_that_advertises_it(monkeypatch, tmp_path, supports_reuse):
    """An older resident denies the unknown ``current_action`` field, so it gets
    the two-field request and still diagnoses the miss; the caller composes."""

    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_store_policy
    from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

    diagnostic = native_store_policy.APPROVAL_REUSE_DIAGNOSTIC_FEATURE
    composed = native_store_policy.APPROVAL_REUSE_DIAGNOSTIC_REUSE_FEATURE
    features = (diagnostic, composed) if supports_reuse else (diagnostic,)
    sent: list[tuple[dict[str, object], str]] = []

    def resident(*, request, required_feature, status, **_kwargs):
        assert status.capabilities.features == features
        sent.append((dict(request), required_feature))
        payload: dict[str, object] = {"reason": "approval_reuse_content_changed", "stored_hash": "sha256:" + "a" * 64}
        if "current_action" in request:
            payload["reuse"] = {"action": "review"}
        return {
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(
        native_store_policy,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=None, capabilities=SimpleNamespace(features=features)),
    )
    monkeypatch.setattr(native_store_policy, "_resident_request", resident)

    reason, stored_hash, reuse = native_store_policy.native_approval_reuse_miss(
        store_path=tmp_path / "guard.db",
        guard_home=tmp_path,
        harness="codex",
        artifact_id="codex:artifact",
        artifact_hash=None,
        workspace=None,
        publisher=None,
        now="2026-10-20T00:00:00Z",
        evidence_provider=lambda *_args: {},
        current_action="review",
    )

    assert (reason, stored_hash) == ("approval_reuse_content_changed", "sha256:" + "a" * 64)
    assert [("current_action" in request, feature) for request, feature in sent] == [
        (supports_reuse, composed if supports_reuse else diagnostic)
    ]
    assert reuse == ({"action": "review"} if supports_reuse else None)
