"""The command lease names Guard Cloud's live policy revision; a move wakes cloud sync."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.cloud_policy_revision import (
    observe_cloud_policy_revision,
    register_cloud_policy_wake,
    reset_cloud_policy_revisions,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    EXACT_CLOUD_REVIEW_PROTOCOL_VERSION,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import lease_next_job


def test_lease_hands_both_routes_policy_revision_to_the_observer() -> None:
    seen: list[dict[str, object]] = []
    exact_response = {
        "item": None,
        "policyRevision": "v4@2000",
        "protocolVersion": EXACT_CLOUD_REVIEW_PROTOCOL_VERSION,
    }
    queue_response = {"item": None, "policyRevision": "v4@2000"}

    assert (
        lease_next_job(
            operations=(EXACT_CLOUD_REVIEW_OPERATION, "guard.app.status"),
            wait_ms=0,
            exact_request=lambda _options: exact_response,
            queue_request=lambda _options: queue_response,
            observe_response=seen.append,
        )
        is None
    )
    assert seen == [exact_response, queue_response]


def test_policy_revision_wakes_only_when_it_moves(tmp_path: Path) -> None:
    reset_cloud_policy_revisions()
    wakes: list[str] = []
    key = str(tmp_path)
    unregister = register_cloud_policy_wake(key, lambda: wakes.append("wake"))
    try:
        # Older Guard Cloud omits the field; a malformed value is ignored.
        assert observe_cloud_policy_revision(key, {"item": None}) is False
        assert observe_cloud_policy_revision(key, {"policyRevision": 7}) is False
        assert observe_cloud_policy_revision(key, {"policyRevision": "x" * 129}) is False
        # The first revision is the baseline; the startup sync already covers it.
        assert observe_cloud_policy_revision(key, {"policyRevision": None}) is False
        # A first published policy, then a rollback, each wake the loop once.
        assert observe_cloud_policy_revision(key, {"policyRevision": "v1@1000"}) is True
        assert observe_cloud_policy_revision(key, {"policyRevision": "v1@1000"}) is False
        assert observe_cloud_policy_revision(key, {"policyRevision": "v0@3000"}) is True
        # Removing the live policy is a change to fetch too.
        assert observe_cloud_policy_revision(key, {"policyRevision": None}) is True
        # Another Guard home never wakes this one.
        assert observe_cloud_policy_revision(str(tmp_path / "other"), {"policyRevision": "v9@1"}) is False
        assert observe_cloud_policy_revision(str(tmp_path / "other"), {"policyRevision": "v9@2"}) is True
    finally:
        unregister()
        reset_cloud_policy_revisions()
    assert wakes == ["wake", "wake", "wake"]
