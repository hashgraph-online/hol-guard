"""The artifact hook gathers the reuse facts and runs the reuse plan's effects, and holds no branch of its own.

``commands_hook_native_reuse`` builds the facts the resident decodes (every
field explicit, the saved query less its action), claims the saved approval a
plan names, and falls to the package floor when the resident cannot plan a
package request. The plan itself is checked against the frozen ladder in
``test_artifact_reuse_step_parity.py``.
"""

from __future__ import annotations

import itertools
import sqlite3
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_reuse_step as step
from codex_plugin_scanner.guard.cli import commands_hook_native_reuse as reuse
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

CONTENT_CHANGED = "approval_reuse_content_changed"

# --- The facts the hook gathers ------------------------------------------------


def _lookup(facts: dict[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], facts["lookup"])


def _artifact() -> GuardArtifact:
    return GuardArtifact("a", "a", "codex", "tool_action_request", "project", "/tmp/hooks.json", command="ls")


def _facts(**overrides: Any) -> dict[str, object]:
    saved: dict[str, Any] = dict.fromkeys(reuse._SAVED_KEYS)
    saved.update(stored_present=True, stored_action="allow", integrity_failure=False, cursor_native_present=False)
    query = {"current_action": "review", **saved}
    inputs: dict[str, Any] = {
        "store": object(),
        "artifact": _artifact(),
        "artifact_hash": "runtime-context-token",
        "current_action": "review",
        "claim_saved_approval": True,
        "remembered_rule_rejected": False,
        "stored_decision": {
            "action": "allow",
            "artifact_hash": "stored-token",
            "source": "approval-gate-once",
            "request_id": "request-1",
            "approval_id": "approval-1",
            "_approval_authority_revision": 3,
        },
        "saved_reuse": {"query": query, "answer": {"action": "allow"}},
        "package_reasons": None,
        "package_policy_action": None,
        "workflow_descriptor": None,
        "trusted_override_hash": None,
        "claimed_hash": None,
        "post_claim_refresh_failed": False,
        "workflow_capability_required": False,
        "workflow_authorization_claimed": False,
        "claimed_trusted_request_override": False,
        "claimed_package_approval_consumed": False,
    }
    inputs.update(overrides)
    return reuse.reuse_step_facts(**inputs)


def test_a_tool_requests_facts_name_every_field_the_resident_decodes() -> None:
    facts = _facts()
    assert set(facts) == step._INPUT_FIELDS
    assert facts["stored"] == {
        "action": "allow",
        "artifact_hash": "stored-token",
        "source": "approval-gate-once",
        "request_id": "request-1",
    }
    lookup = facts["lookup"]
    assert isinstance(lookup, dict) and lookup["mode"] == "tool" and lookup["workflow_preflight"] is False
    saved = lookup["saved"]
    assert isinstance(saved, dict) and set(saved) == set(reuse._SAVED_KEYS) and "current_action" not in saved
    assert facts["trusted_override"] is None and facts["claimed"] is None


def test_a_decision_without_a_complete_authority_names_no_request() -> None:
    row = _facts(stored_decision={"action": "allow", "artifact_hash": "stored-token", "source": "manual"})["stored"]
    assert isinstance(row, dict) and row["request_id"] is None
    assert _facts(stored_decision=None)["stored"] is None


@pytest.mark.parametrize(
    "saved_reuse",
    [None, {}, {"query": None}, {"query": {"current_action": "review"}}, {"query": "review"}],
)
def test_a_tool_request_without_a_saved_query_fails_closed(saved_reuse: object) -> None:
    with pytest.raises(NativeHookDecisionError):
        _facts(saved_reuse=saved_reuse)


def test_the_workflow_preflight_is_read_only_for_a_request_that_can_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    def preflight(store: object, request_id: str, descriptor: object) -> bool:
        calls.append((request_id, descriptor))
        return True

    monkeypatch.setattr(reuse, "resolved_github_workflow_capability_preflight", preflight)
    descriptor: Any = object()
    pending = _facts(workflow_descriptor=descriptor)["lookup"]
    assert isinstance(pending, dict) and pending["workflow_preflight"] is True
    assert calls == [("request-1", descriptor)]
    assert _lookup(_facts(workflow_descriptor=None))["workflow_preflight"] is False
    assert _lookup(_facts(workflow_descriptor=descriptor, stored_decision=None))["workflow_preflight"] is False
    assert len(calls) == 1


def test_a_workflow_preflight_the_store_cannot_read_is_not_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreadable(store: object, request_id: str, descriptor: object) -> bool:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(reuse, "resolved_github_workflow_capability_preflight", unreadable)
    descriptor: Any = object()
    assert _lookup(_facts(workflow_descriptor=descriptor))["workflow_preflight"] is False

    def corrupt(store: object, request_id: str, descriptor: object) -> bool:
        raise RuntimeError("not a store error")

    monkeypatch.setattr(reuse, "resolved_github_workflow_capability_preflight", corrupt)
    with pytest.raises(RuntimeError):
        _facts(workflow_descriptor=descriptor)


def test_a_package_requests_facts_carry_its_evaluation_reasons() -> None:
    reasons = [{"code": "saved_package_approval", "approval_claim_disposition": "consumed"}]
    facts = _facts(package_reasons=reasons, package_policy_action="review", saved_reuse=None)
    lookup = _lookup(facts)
    assert lookup == {"mode": "package", "reasons": reasons, "evaluation_policy_action": "review"}
    assert lookup["reasons"][0] is not reasons[0]


def _stub_token_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Token comparison is the native authority's; the facts only carry its verdict."""

    monkeypatch.setattr(
        reuse,
        "approval_context_tokens_validation_reason",
        lambda saved, current: None if saved == current else CONTENT_CHANGED,
    )
    monkeypatch.setattr(
        reuse,
        "_runtime_saved_allow_validation_reason",
        lambda decision, *, artifact, artifact_hash: (
            None if decision["artifact_hash"] == artifact_hash else CONTENT_CHANGED
        ),
    )


def test_override_and_claimed_facts_carry_the_token_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_token_validation(monkeypatch)
    changed = _facts(trusted_override_hash="stored-token", claimed_hash="runtime-context-token")
    override, claimed = changed["trusted_override"], changed["claimed"]
    assert isinstance(override, dict) and set(override) == {"token_validation_reason", "stored_validation_reason"}
    assert override["token_validation_reason"] == CONTENT_CHANGED
    assert override["stored_validation_reason"] == CONTENT_CHANGED
    assert isinstance(claimed, dict) and claimed["claimed_hash"] == "runtime-context-token"
    assert set(claimed) == {
        "claimed_hash",
        "token_validation_reason",
        "post_claim_refresh_failed",
        "workflow_capability_required",
        "workflow_authorization_claimed",
        "claimed_trusted_request_override",
        "claimed_package_approval_consumed",
    }
    assert claimed["token_validation_reason"] is None
    drifted = _facts(claimed_hash="another-token")["claimed"]
    assert cast(dict[str, Any], drifted)["token_validation_reason"] == CONTENT_CHANGED
    assert _facts(trusted_override_hash="stored-token", stored_decision=None)["trusted_override"] == {
        "token_validation_reason": CONTENT_CHANGED,
        "stored_validation_reason": None,
    }
    same = _facts(
        artifact_hash="token",
        trusted_override_hash="token",
        claimed_hash="token",
        stored_decision={"action": "allow", "artifact_hash": "token", "source": "manual"},
    )
    assert same["trusted_override"] == {"token_validation_reason": None, "stored_validation_reason": None}
    assert cast(dict[str, Any], same["claimed"])["token_validation_reason"] is None


@pytest.mark.parametrize("scope", ["artifact", "workspace", "publisher", "harness", "global"])
def test_the_scope_that_carried_a_saved_allow_never_reaches_the_resident(scope: str) -> None:
    """Always allow is honored at any scope: the facts carry no scope for reuse to read."""

    decision = {
        "action": "allow",
        "artifact_hash": "stored-token",
        "source": "approval-gate",
        "request_id": "request-1",
        "approval_id": "approval-1",
        "_approval_authority_revision": 3,
    }
    assert _facts(stored_decision={**decision, "scope": scope, "approval_scope": scope}) == _facts(
        stored_decision=decision
    )


# --- The effects the hook runs -------------------------------------------------


def test_a_claim_is_made_only_for_a_decision_the_plan_was_given() -> None:
    class Store:
        def __init__(self, won: object) -> None:
            self.won, self.calls = won, []

        def claim_approval_reuse_decision(self, decision: object, *, now: str) -> object:
            self.calls.append((decision, now))
            return self.won

    decision = {"action": "allow", "request_id": "request-1"}
    won, lost = Store(1), Store(None)
    assert reuse.claim_saved_decision(won, decision, now="t0") is True
    assert reuse.claim_saved_decision(lost, decision, now="t1") is False
    assert won.calls == [(decision, "t0")]
    with pytest.raises(NativeHookDecisionError):
        reuse.claim_saved_decision(won, None, now="t2")
    assert len(won.calls) == 1


def test_a_lost_claim_takes_the_branch_the_plan_names() -> None:
    settled = step.ReuseSettled("review", None, False, None, (), None, False)
    plan = step.ReuseClaim(step.ReuseRevalidate(False, False, "request-1"), settled)
    outcomes = itertools.cycle([False])
    assert reuse.execute_reuse_plan(plan, claim=lambda: next(outcomes), revalidate=lambda _s: "revalidated") is settled
    assert reuse.execute_reuse_plan(plan, claim=lambda: True, revalidate=lambda _s: "revalidated") == "revalidated"


# --- The package floor: the one decision Python keeps --------------------------


def _floor_facts(
    *, current_action: str = "review", stored_action: str | None = None, extra: dict[str, object] | None = None
) -> dict[str, Any]:
    stored = (
        None
        if stored_action is None
        else {"action": stored_action, "artifact_hash": "h", "source": "s", "request_id": None}
    )
    return {
        "current_action": current_action,
        "stored": stored,
        "trusted_override": None,
        "claimed": None,
        **(extra or {}),
    }


@pytest.mark.parametrize(("disposition", "consumed"), [("consumed", True), ("retained", False)])
def test_the_floor_revalidates_a_claimed_saved_allow(disposition: str, consumed: bool) -> None:
    floor = reuse.package_reuse_floor(_floor_facts(), claimed_disposition=disposition)
    assert floor == step.ReuseRevalidate(False, consumed, None)


def test_the_floor_defers_to_the_resident_for_an_override_or_a_claimed_pass() -> None:
    extras: tuple[dict[str, object], ...] = ({"trusted_override": {"x": 1}}, {"claimed": {"x": 1}})
    for extra in extras:
        assert reuse.package_reuse_floor(_floor_facts(extra=extra), claimed_disposition=None) is None


@pytest.mark.parametrize("current_action", ["allow", "review", "require-reapproval", "block"])
def test_the_floor_never_lifts_a_stored_block_or_weakens_the_action(current_action: str) -> None:
    blocked = reuse.package_reuse_floor(
        _floor_facts(current_action=current_action, stored_action="block"), claimed_disposition=None
    )
    assert isinstance(blocked, step.ReuseSettled)
    assert blocked.policy_action == "block" and blocked.package_risk_refresh is (current_action != "block")
    assert (
        blocked.approval_reuse is not None
        and blocked.approval_reuse["reason_code"] == "approval_reuse_authority_unavailable"
    )
    assert [entry["source"] for entry in blocked.evidence] == ["approval_reuse"]
    plain = reuse.package_reuse_floor(
        _floor_facts(current_action=current_action, stored_action="allow"), claimed_disposition=None
    )
    assert isinstance(plain, step.ReuseSettled)
    assert plain.policy_action == current_action and plain.package_risk_refresh is False
    assert plain.approval_reuse is None and plain.evidence == () and plain.approval_reuse_source is None
