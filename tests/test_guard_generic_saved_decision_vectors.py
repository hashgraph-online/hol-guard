"""Saved-decision lookups ask the resident only what it advertises.

The Rust resident replays the recorded generic-hook saved-decision vectors in
``policy_lookup_groups_tests.rs``. Here a runtime without the group-expansion
capability is never sent unexpanded groups, and an approval-reuse miss names
the current action only to a resident that advertises it.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import POLICY_LOOKUP_MEMORY_FEATURE, PolicyLookupEvidence


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
