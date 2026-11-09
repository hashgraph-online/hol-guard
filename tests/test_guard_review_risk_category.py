"""The review claim names the same risk level as the Cloud Review event."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.review_claim_hashing import compute_local_review_request_claim_hash
from codex_plugin_scanner.guard.review_contracts import (
    GuardReviewContractError,
    _risk_category,
    build_local_review_request_claim,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    _oauth_metadata,
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"risk_headline": "Destructive delete of the build cache", "policy_action": "allow"}, "high"),
        ({"risk_headline": "Reads a project file", "risk_summary": "Needs review", "policy_action": "allow"}, "medium"),
        ({"policy_action": "require-reapproval"}, "medium"),
        ({"policy_action": "block"}, "high"),
        ({"risk_headline": "low effort, high impact"}, "high"),
        ({"risk_headline": "Blocked writes to the keychain"}, "high"),
        ({"risk_headline": "Reviewing a follow-up"}, "medium"),
        ({"risk_headline": "Allows highlighting"}, "low"),
        ({"risk_headline": "follow the highlight", "policy_action": "sandbox-required"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_risk_category_matches_whole_words_and_their_inflections(row: dict[str, object], expected: str) -> None:
    assert _risk_category(row) == expected


def _upgraded_request_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # "Allowlist" named Low under the substring rule and names no level now,
    # so this request's claim hash moved when the word rule shipped.
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, replace(review_request("risk-upgrade"), risk_headline="Allowlist update"))
    enable_exact_cloud_review(store)
    monkeypatch.setattr(store, "list_review_event_snapshots", lambda _request_id: [])
    row = store.get_raw_approval_request_snapshot("risk-upgrade")
    assert isinstance(row, dict)
    oauth = _oauth_metadata(store)
    uploaded = build_local_review_request_claim(request_row=row, oauth=oauth, store=store, substring_risk_rule=True)
    current = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    assert (uploaded["riskCategory"], current["riskCategory"]) == ("low", "medium")
    return store, uploaded


def test_reply_to_a_claim_uploaded_before_the_word_rule_still_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, uploaded = _upgraded_request_store(tmp_path, monkeypatch)

    resolution = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, "risk-upgrade", receipt_id="pre-update-claim", source_claim=uploaded),
    )

    assert resolution.action == "allow"


def test_a_risk_level_neither_rule_names_still_breaks_the_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, uploaded = _upgraded_request_store(tmp_path, monkeypatch)
    forged = {**uploaded, "riskCategory": "high"}
    forged["claimHash"] = compute_local_review_request_claim_hash(forged)

    with pytest.raises((ExactCloudReviewError, GuardReviewContractError)):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval(store, "risk-upgrade", receipt_id="forged-level", source_claim=forged),
        )
