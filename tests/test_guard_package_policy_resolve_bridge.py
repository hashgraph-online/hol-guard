"""The stored-policy bridge hydrates facts and fails closed on any bad native reply."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_package_policy_resolve as bridge
from codex_plugin_scanner.guard.runtime import command_queue_drain


class _Store:
    guard_home = Path("/tmp/guard-home-bridge")

    def __init__(self, decision: dict[str, object] | None) -> None:
        self.decision = decision
        self.claims: list[str] = []

    def resolve_policy_decision_lookup(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        return {"decision": self.decision, "ignored_local_integrity": None}

    def approval_reuse_diagnostic(self, *_args: object) -> tuple[None, None]:
        return None, None

    def claim_approval_reuse_decision(self, _decision: object, *, now: str) -> bool:
        self.claims.append(now)
        return False


def _call(store: _Store, **overrides: object) -> tuple[object, ...]:
    evaluation = SimpleNamespace(policy_action="review", reasons=(), packages=())
    artifact = SimpleNamespace(harness="codex", artifact_id="command:npm", publisher=None)
    kwargs: dict[str, object] = {
        "store": store,
        "artifact": artifact,
        "artifact_hash": "hash",
        "workspace_dir": Path("/work"),
        "now": "2026-07-17T00:00:00Z",
        "policy_workspaces": ("ws",),
        "current_action": None,
        "claim_saved_approval": True,
    }
    kwargs.update(overrides)
    return bridge.native_resolve_stored_package_policy(evaluation, **kwargs)  # type: ignore[arg-type]


def test_no_saved_facts_skips_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("resident must not be called")

    monkeypatch.setattr(bridge, "_transport", forbidden)
    evaluation, disposition, reused = _call(_Store(None))
    assert evaluation.policy_action == "review"  # type: ignore[attr-defined]
    assert (disposition, reused) == (None, None)


@pytest.mark.parametrize(
    "payload",
    [
        {"patch": {}, "claim": "bogus", "claim_disposition": None, "reused": False},
        {"patch": {}, "claim": None, "claim_disposition": "maybe", "reused": False},
        {"patch": [], "claim": None, "claim_disposition": None, "reused": False},
        {"patch": {}, "claim": None, "claim_disposition": None},
    ],
)
def test_malformed_reply_fails_closed(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    monkeypatch.setattr(bridge, "_transport", lambda *_a, **_k: payload)
    decision = {"action": "allow", "decision_id": 1}
    with pytest.raises(bridge.NativePackagePolicyResolveError):
        _call(_Store(decision))


def _verdict_patch(policy_action: str) -> dict[str, object]:
    return {
        "decision": policy_action,
        "policy_action": policy_action,
        "risk_summary": policy_action,
        "record_monitor_evidence": False,
        "user_copy": {
            "title": policy_action,
            "summary": policy_action,
            "next_step": None,
            "dashboard_url": None,
            "harness_message": policy_action,
        },
    }


def test_failed_claim_repeats_the_request_with_the_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, object]] = []
    replies = iter(
        [
            {
                "patch": _verdict_patch("allow"),
                "claim": "store",
                "claim_disposition": "retained",
                "reused": True,
            },
            {
                "patch": _verdict_patch("review"),
                "claim": None,
                "claim_disposition": None,
                "reused": False,
            },
        ]
    )

    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        requests.append(dict(request))
        return next(replies)

    monkeypatch.setattr(bridge, "_transport", transport)
    monkeypatch.setattr(bridge, "apply_package_evaluation_patch", lambda evaluation, _patch: evaluation)
    store = _Store({"action": "allow", "decision_id": 1})
    _evaluation, disposition, reused = _call(store)
    assert store.claims == ["2026-07-17T00:00:00Z"]
    assert "claim_succeeded" not in requests[0]
    assert requests[1]["claim_succeeded"] is False
    assert (disposition, reused) == (None, None)


class _MovingStore(_Store):
    """A saved allow whose revision a sibling approval moves before the first claim."""

    def __init__(self, decisions: list[dict[str, object]], outcomes: list[bool]) -> None:
        super().__init__(decisions[0])
        self._decisions = iter(decisions)
        self._outcomes = iter(outcomes)

    def resolve_policy_decision_lookup(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        self.decision = next(self._decisions)
        return {"decision": self.decision, "ignored_local_integrity": None}

    def claim_approval_reuse_decision(self, decision: object, *, now: str) -> bool:
        assert isinstance(decision, dict)
        self.claims.append(str(decision["_approval_authority_revision"]))
        return next(self._outcomes)


def _reuse_store_reply() -> dict[str, object]:
    reply: dict[str, object] = {
        "patch": _verdict_patch("allow"),
        "claim": "store",
        "claim_disposition": "retained",
        "reused": True,
    }
    return reply


def test_a_claim_refused_for_a_moved_revision_reads_the_allow_again(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, object]] = []

    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        requests.append(dict(request))
        return _reuse_store_reply()

    monkeypatch.setattr(bridge, "_transport", transport)
    monkeypatch.setattr(bridge, "apply_package_evaluation_patch", lambda evaluation, _patch: evaluation)
    saved: dict[str, object] = {"action": "allow", "decision_id": 7}
    store = _MovingStore(
        [{**saved, "_approval_authority_revision": 4}, {**saved, "_approval_authority_revision": 5}],
        [False, True],
    )

    _evaluation, disposition, reused = _call(store)

    assert store.claims == ["4", "5"]
    assert all("claim_succeeded" not in request for request in requests)
    assert disposition == "retained"
    assert reused == {**saved, "_approval_authority_revision": 5}


def test_every_sibling_in_a_full_bulk_approval_landing_first_still_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    # Guard settles a full lease batch of Cloud Review jobs at once, and each
    # sibling allow can move the authority revision once before this claim.
    siblings = command_queue_drain.REVIEW_LEASE_BATCH_SIZE - 1

    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        if request.get("claim_succeeded") is False:
            return _reply(patch=_verdict_patch("review"))
        return _reuse_store_reply()

    monkeypatch.setattr(bridge, "_transport", transport)
    monkeypatch.setattr(bridge, "apply_package_evaluation_patch", lambda evaluation, _patch: evaluation)
    saved: dict[str, object] = {"action": "allow", "decision_id": 7}
    store = _MovingStore(
        [{**saved, "_approval_authority_revision": revision} for revision in range(1, siblings + 2)],
        [False] * siblings + [True],
    )

    _evaluation, disposition, reused = _call(store)

    assert store.claims == [str(revision) for revision in range(1, siblings + 2)]
    assert disposition == "retained"
    assert reused == {**saved, "_approval_authority_revision": siblings + 1}


def test_a_claim_refused_at_an_unmoved_revision_is_not_tried_again(monkeypatch: pytest.MonkeyPatch) -> None:
    replies = iter([_reuse_store_reply(), _reply(patch=_verdict_patch("review"))])
    monkeypatch.setattr(bridge, "_transport", lambda *_args, **_kwargs: next(replies))
    monkeypatch.setattr(bridge, "apply_package_evaluation_patch", lambda evaluation, _patch: evaluation)
    saved: dict[str, object] = {"action": "allow", "decision_id": 7, "_approval_authority_revision": 4}
    store = _MovingStore([saved, saved], [False])

    _evaluation, disposition, reused = _call(store)

    assert store.claims == ["4"]
    assert (disposition, reused) == (None, None)


def test_a_different_row_at_the_new_revision_is_not_claimed_in_its_place(monkeypatch: pytest.MonkeyPatch) -> None:
    replies = iter([_reuse_store_reply(), _reply(patch=_verdict_patch("review"))])
    monkeypatch.setattr(bridge, "_transport", lambda *_args, **_kwargs: next(replies))
    monkeypatch.setattr(bridge, "apply_package_evaluation_patch", lambda evaluation, _patch: evaluation)
    store = _MovingStore(
        [
            {"action": "allow", "decision_id": 7, "_approval_authority_revision": 4},
            {"action": "allow", "decision_id": 8, "_approval_authority_revision": 5},
        ],
        [False],
    )

    _evaluation, disposition, reused = _call(store)

    assert store.claims == ["4"]
    assert (disposition, reused) == (None, None)


def _reply(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "patch": _verdict_patch("allow"),
        "claim": None,
        "claim_disposition": None,
        "reused": False,
    }
    payload.update(overrides)
    return payload


def test_empty_patch_does_not_skip_a_saved_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_transport", lambda *_args, **_kwargs: _reply(patch={}))
    with pytest.raises(bridge.NativePackagePolicyResolveError):
        _call(_Store({"action": "allow", "decision_id": 1}))


def test_incomplete_patch_does_not_skip_a_saved_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        bridge,
        "_transport",
        lambda *_args, **_kwargs: _reply(patch={"policy_action": "block"}),
    )
    with pytest.raises(bridge.NativePackagePolicyResolveError):
        _call(_Store({"action": "block", "decision_id": 1}))


def test_unclaimed_allow_and_failed_retry_reuse_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        if request.get("claim_succeeded") is False:
            return _reply(reused=True)
        return _reply(claim="store", claim_disposition="consumed", reused=True)

    monkeypatch.setattr(bridge, "_transport", transport)
    saved = {"action": "allow", "decision_id": 1}
    with pytest.raises(bridge.NativePackagePolicyResolveError):
        _call(_Store(saved), claim_saved_approval=False)
    with pytest.raises(bridge.NativePackagePolicyResolveError):
        _call(_Store(saved))


def test_a_new_allow_without_reuse_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_transport", lambda *_args, **_kwargs: _reply())
    with pytest.raises(bridge.NativePackagePolicyResolveError):
        _call(_Store({"action": "block", "decision_id": 1}))


def test_stale_family_block_keeps_the_current_evaluation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_transport", lambda *_args, **_kwargs: _reply(patch={}))
    monkeypatch.setattr(bridge, "_bundle_rules", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(bridge, "apply_package_evaluation_patch", lambda evaluation, patch: (evaluation, patch)[0])
    decision = {
        "action": "block",
        "artifact_hash": None,
        "artifact_id": "family:package-request",
        "decision_id": 3,
        "owner": "rule-1",
        "scope": "harness",
        "source": "policy-bundle",
    }
    evaluation, disposition, reused = _call(_Store(decision))
    assert evaluation.policy_action == "review"  # type: ignore[attr-defined]
    assert (disposition, reused) == (None, None)
