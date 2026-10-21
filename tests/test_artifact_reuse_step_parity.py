"""The artifact hook runs the resident's reuse plan exactly as the retired Python ladder behaved.

``scripts/ci/record_artifact_reuse_step_vectors.py`` froze the old Python
approval-reuse ladder as an oracle and recorded, for every fact set it walked,
the plan tree that ladder exhibits (one branch per outcome of each store
claim). The Rust suite replays the vectors through the resident. This suite
feeds every recorded plan to the new client and executor with the store and the
revalidation stubbed, and compares the effect trace, the claims made and the
final verdict with an independent walk of the recorded plan.

The approval invariant (``docs/guard/approval-invariant.md``) is checked over
the same vectors: Allow once keeps its retry binding, Always allow is honored
at any scope and under ``require-reapproval``, a changed or expired hash is
refused, and a claimed approval is never silently lost.
"""

from __future__ import annotations

import copy
import dataclasses
import functools
import gzip
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_reuse_step as step
from codex_plugin_scanner.guard.cli import commands_hook_native_reuse as reuse
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError
from codex_plugin_scanner.guard.runtime.approval_reuse import _decision_from_native_payload

VECTORS = (
    Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/tests/fixtures/artifact_reuse_step_vectors.json.gz"
)
CONTENT_CHANGED = "approval_reuse_content_changed"
IDENTITY_CHANGED = "approval_reuse_identity_changed"
REVIEW_TIER = ("review", "require-reapproval")

Vector = dict[str, Any]


@functools.cache
def _vectors() -> tuple[Vector, ...]:
    return tuple(json.loads(gzip.decompress(VECTORS.read_bytes())))


# --- An independent reading of a recorded plan --------------------------------


def _nodes(plan: Vector, via: str = "root", lost: bool = False) -> Iterator[tuple[Vector, str, bool]]:
    """Every node with how it was reached: ``root``, ``claimed`` or ``failed`` (a lost claim)."""

    yield plan, via, lost
    if plan["effect"] == "claim":
        yield from _nodes(plan["on_claimed"], "claimed", lost)
        yield from _nodes(plan["on_failed"], "failed", True)


def _outcome_paths(plan: Vector) -> Iterator[tuple[bool, ...]]:
    """Each sequence of store-claim outcomes the plan can meet."""

    if plan["effect"] != "claim":
        yield ()
        return
    for won in (True, False):
        for rest in _outcome_paths(plan["on_claimed" if won else "on_failed"]):
            yield (won, *rest)


def _expected(plan: Vector, outcomes: tuple[bool, ...]) -> tuple[list[tuple[Any, ...]], tuple[Any, ...]]:
    trace: list[tuple[Any, ...]] = []
    queue = list(outcomes)
    node = plan
    while node["effect"] == "claim":
        won = queue.pop(0)
        trace.append(("claim", won))
        node = node["on_claimed" if won else "on_failed"]
    assert not queue
    if node["effect"] == "revalidate":
        step_args = (node["trusted_request_override"], node["package_approval_consumed"], node["request_id"])
        trace.append(("revalidate", *step_args))
        return trace, ("revalidated", *step_args)
    return trace, ("settled", {key: value for key, value in node.items() if key != "effect"})


def _executed(parsed: step.ReusePlan, outcomes: tuple[bool, ...]) -> tuple[list[tuple[Any, ...]], tuple[Any, ...]]:
    trace: list[tuple[Any, ...]] = []
    queue = list(outcomes)

    def claim() -> bool:
        won = queue.pop(0)
        trace.append(("claim", won))
        return won

    def revalidate(planned: step.ReuseRevalidate) -> tuple[Any, ...]:
        args = (planned.trusted_request_override, planned.package_approval_consumed, planned.request_id)
        trace.append(("revalidate", *args))
        return ("revalidated", *args)

    verdict = reuse.execute_reuse_plan(parsed, claim=claim, revalidate=revalidate)
    assert not queue
    if isinstance(verdict, step.ReuseSettled):
        fields = dataclasses.asdict(verdict)
        fields["evidence"] = list(fields["evidence"])
        return trace, ("settled", fields)
    return trace, verdict


def _resident(monkeypatch: pytest.MonkeyPatch, plan: object, *, kind: str = "artifact_reuse_step") -> list[Any]:
    """Stub the resident round trip with ``plan`` as its bound reply."""

    sent: list[Any] = []

    def decide(query: Any, guard_home: Any, validate: Callable[[dict[str, Any]], None], feature: str) -> dict[str, Any]:
        sent.append((query, feature))
        if kind != query["kind"]:  # the shared resident layer binds the reply to the query kind
            raise NativeHookDecisionError("native_hook_decision_invalid")
        validate({"kind": kind, "plan": plan})
        return {}

    monkeypatch.setattr(step, "_decide", decide)
    return sent


def _plan_for(monkeypatch: pytest.MonkeyPatch, vector: Vector) -> step.ReusePlan:
    _resident(monkeypatch, vector["plan"])
    return step.native_artifact_reuse_step(vector["facts"])


# --- Parity with the frozen ladder ---------------------------------------------


def test_every_recorded_plan_runs_as_the_ladder_did(monkeypatch: pytest.MonkeyPatch) -> None:
    claims = paths = 0
    for vector in _vectors():
        sent = _resident(monkeypatch, vector["plan"])
        parsed = step.native_artifact_reuse_step(vector["facts"])
        assert sent == [
            ({"kind": "artifact_reuse_step", "inputs": vector["facts"]}, "hook-decision-artifact-reuse-step-v1")
        ]
        for outcomes in _outcome_paths(vector["plan"]):
            assert _executed(parsed, outcomes) == _expected(vector["plan"], outcomes), vector["facts"]
            paths += 1
        claims += sum(node["effect"] == "claim" for node, _, _ in _nodes(vector["plan"]))
    assert len(_vectors()) > 6000
    assert claims > 100 and paths > len(_vectors())


def test_a_tool_settlement_carries_a_native_reuse_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    checked = 0
    for vector in _vectors():
        if vector["facts"]["lookup"]["mode"] != "tool":
            continue
        for node, _, _ in _nodes(vector["plan"]):
            if node["effect"] == "settled":
                assert _decision_from_native_payload(node["approval_reuse"]).to_evidence() == node["approval_reuse"]
                checked += 1
    assert checked > 1000


def test_a_resident_failure_is_never_planned_around(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise NativeHookDecisionError("native_hook_decision_unavailable")

    monkeypatch.setattr(step, "_decide", refuse)
    for vector in _vectors()[:50]:
        with pytest.raises(NativeHookDecisionError):
            step.native_artifact_reuse_step(vector["facts"])


# --- A reply that is not a bound, strict plan fails closed ---------------------


def _vector(predicate: Callable[[Vector], bool]) -> Vector:
    return next(copy.deepcopy(vector) for vector in _vectors() if predicate(vector))


def _plain_tool(vector: Vector) -> bool:
    facts = vector["facts"]
    return facts["lookup"]["mode"] == "tool" and facts["trusted_override"] is None and facts["claimed"] is None


def _lost_claim_plan() -> Vector:
    return _vector(lambda v: v["plan"]["effect"] == "claim" and _plain_tool(v))


def _malformed_plans() -> Iterator[tuple[str, Vector, Callable[[Vector], object]]]:
    claim = _lost_claim_plan()
    settled = _vector(lambda v: v["plan"]["effect"] == "settled" and _plain_tool(v))
    package = _vector(lambda v: v["plan"]["effect"] == "settled" and v["facts"]["lookup"]["mode"] == "package")

    def at(vector: Vector, *path: str) -> Vector:
        node = vector["plan"]
        for key in path:
            node = node[key]
        return node

    yield "unknown effect", settled, lambda v: v["plan"].update(effect="allow")
    yield "extra settled field", settled, lambda v: v["plan"].update(extra=1)
    yield "missing settled field", settled, lambda v: v["plan"].pop("evidence")
    yield "action not a guard action", settled, lambda v: v["plan"].update(policy_action="permit")
    yield "action not a string", settled, lambda v: v["plan"].update(policy_action=1)
    yield "evidence entry not an object", settled, lambda v: v["plan"].update(evidence=["audit"])
    yield "flag not a bool", settled, lambda v: v["plan"].update(package_risk_refresh="no")
    yield "tool settlement without a reuse decision", settled, lambda v: v["plan"].update(approval_reuse=None)
    yield "tool reuse decision malformed", settled, lambda v: v["plan"].update(approval_reuse={"action": "allow"})
    yield "package reuse evidence not an object", package, lambda v: v["plan"].update(approval_reuse="allow")
    yield "claim wins into a settlement", claim, lambda v: v["plan"].update(on_claimed=at(v, "on_failed"))
    yield "claim loses into a revalidation", claim, lambda v: v["plan"].update(on_failed=at(v, "on_claimed"))
    yield "claim without a failure branch", claim, lambda v: v["plan"].pop("on_failed")
    yield "claim with extra field", claim, lambda v: v["plan"].update(extra=1)
    yield "revalidation flag not a bool", claim, lambda v: at(v, "on_claimed").update(package_approval_consumed=0)
    yield "revalidation request id not a string", claim, lambda v: at(v, "on_claimed").update(request_id=7)

    def too_deep(vector: Vector) -> None:
        node = vector["plan"]
        failed = copy.deepcopy(at(vector, "on_failed"))
        for _ in range(3):
            node["on_failed"] = {"effect": "claim", "on_claimed": at(vector, "on_claimed"), "on_failed": failed}
            node = node["on_failed"]

    yield "plan nested past the ladder", claim, too_deep


@pytest.mark.parametrize(
    ("name", "vector", "edit"), list(_malformed_plans()), ids=lambda value: value if isinstance(value, str) else ""
)
def test_a_malformed_plan_fails_closed(
    monkeypatch: pytest.MonkeyPatch, name: str, vector: Vector, edit: Callable[[Vector], object]
) -> None:
    vector = copy.deepcopy(vector)
    edit(vector)
    _resident(monkeypatch, vector["plan"])
    with pytest.raises(NativeHookDecisionError):
        step.native_artifact_reuse_step(vector["facts"])


def test_a_reply_for_another_query_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    vector = _lost_claim_plan()
    _resident(monkeypatch, vector["plan"], kind="saved_reuse")
    with pytest.raises(NativeHookDecisionError):
        step.native_artifact_reuse_step(vector["facts"])


def test_inputs_that_name_no_request_shape_never_reach_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _lost_claim_plan()["plan"])
    facts = _lost_claim_plan()["facts"]
    cases = [{}, {**facts, "extra": 1}, {**facts, "lookup": {"mode": "workflow"}}, {**facts, "lookup": None}]
    cases.append({key: value for key, value in facts.items() if key != "claimed"})
    for case in cases:
        with pytest.raises(NativeHookDecisionError):
            step.native_artifact_reuse_step(case)
    assert sent == []


# --- The invariant over every recorded fact set --------------------------------


def _live_saved_allow(vector: Vector) -> bool:
    facts = vector["facts"]
    if not _plain_tool(vector) or facts["stored"] is None:
        return False
    saved = facts["lookup"]["saved"]
    return (
        facts["claim_saved_approval"] is True
        and facts["current_action"] == "review"
        and facts["remembered_rule_rejected"] is False
        and saved["stored_action"] == "allow"
        and saved["stored_validation_reason"] is None
        and saved["integrity_failure"] is False
        and isinstance(saved["stored_artifact_hash"], str)
        and saved["stored_artifact_hash"].startswith("guard-approval-context:v1:")
    )


def test_a_won_claim_is_always_revalidated_and_a_revalidation_follows_a_claim() -> None:
    for vector in _vectors():
        facts = vector["facts"]
        for node, via, _ in _nodes(vector["plan"]):
            if node["effect"] == "claim":
                assert node["on_claimed"]["effect"] == "revalidate", facts
                assert node["on_failed"]["effect"] != "revalidate", facts
            if node["effect"] != "revalidate":
                continue
            if facts["lookup"]["mode"] == "tool":
                assert via == "claimed", facts
                continue
            # A package request's resolver may already hold the claim, so its
            # revalidation can also be the root, for a saved package allow.
            if via == "root":
                assert facts["claim_saved_approval"] is True, facts
                assert any(r.get("code") == "saved_package_approval" for r in facts["lookup"]["reasons"]), facts


def test_allow_once_revalidates_the_request_it_was_issued_for() -> None:
    claims = 0
    for vector in _vectors():
        facts = vector["facts"]
        stored_request = (facts["stored"] or {}).get("request_id")
        for node, _, _ in _nodes(vector["plan"]):
            if node["effect"] != "claim":
                continue
            won = node["on_claimed"]
            claims += 1
            assert won["package_approval_consumed"] is False, facts
            assert won["request_id"] == stored_request, facts
            if won["trusted_request_override"]:
                assert facts["trusted_override"] is not None, facts
    assert claims > 100


def test_a_live_saved_allow_is_claimed_before_it_is_used() -> None:
    live = [vector for vector in _vectors() if _live_saved_allow(vector)]
    assert live
    assert all(vector["plan"]["effect"] == "claim" for vector in live)


def test_a_lost_claim_never_allows_a_review_tier_action() -> None:
    lost = 0
    for vector in _vectors():
        facts = vector["facts"]
        if facts["lookup"]["mode"] != "tool" or facts["claimed"] is not None:
            continue
        for node, _, was_lost in _nodes(vector["plan"]):
            if was_lost and node["effect"] == "settled" and facts["current_action"] in REVIEW_TIER:
                assert node["policy_action"] != "allow", facts
                lost += 1
    assert lost > 0


def test_an_expired_or_changed_hash_is_refused_and_never_claimed() -> None:
    refused = 0
    for vector in _vectors():
        facts = vector["facts"]
        if not _plain_tool(vector) or facts["current_action"] not in REVIEW_TIER:
            continue
        saved = facts["lookup"]["saved"]
        if (
            saved["stored_validation_reason"] not in (CONTENT_CHANGED, IDENTITY_CHANGED)
            and saved["diagnostic_reason"] is None
        ):
            continue
        plan = vector["plan"]
        assert plan["effect"] == "settled", facts
        assert plan["approval_reuse"]["status"] == "rejected", facts
        assert plan["policy_action"] != "allow", facts
        refused += 1
    assert refused > 40


def test_an_integrity_failure_is_never_claimed_or_revalidated() -> None:
    checked = 0
    for vector in _vectors():
        if _plain_tool(vector) and vector["facts"]["lookup"]["saved"]["integrity_failure"] is True:
            assert vector["plan"]["effect"] == "settled", vector["facts"]
            checked += 1
    assert checked > 0


def test_a_saved_package_allow_is_honored_under_require_reapproval() -> None:
    retained = consumed = 0
    for vector in _vectors():
        facts = vector["facts"]
        if facts["lookup"]["mode"] != "package":
            continue
        plan = vector["plan"]
        allow = next((r for r in facts["lookup"]["reasons"] if r.get("code") == "saved_package_approval"), None)
        if allow is not None and facts["claim_saved_approval"] is True:
            assert plan["effect"] == "revalidate", facts
            once = allow.get("approval_claim_disposition") == "consumed"
            assert plan["package_approval_consumed"] is once, facts
            if facts["current_action"] == "require-reapproval":
                consumed += once
                retained += not once
        if facts["stored"] is not None and facts["stored"]["action"] == "block" and plan["effect"] == "settled":
            assert plan["policy_action"] == "block", facts
    assert retained > 0 and consumed > 0
