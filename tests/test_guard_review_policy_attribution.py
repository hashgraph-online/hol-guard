"""Review claims name the published Cloud rule that queued them, and keep it."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import review_policy_attribution as attribution_module
from codex_plugin_scanner.guard.review_claim_hashing import compute_local_review_request_claim_hash
from codex_plugin_scanner.guard.review_contracts import build_local_review_request_claim
from codex_plugin_scanner.guard.runtime.exact_cloud_review import _oauth_metadata
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    review_request,
)

_RULE_ID = "review-env-reads"


def _bundle(*, issued_at: datetime, version: str = "policy-1730000000000") -> dict[str, object]:
    return {
        "schemaVersion": "guard-policy-bundle.v1",
        "bundleVersion": version,
        "issuedAt": issued_at.isoformat(),
        "rules": [{"ruleId": _RULE_ID, "action": "review"}, {"ruleId": "allow-docs", "action": "allow"}],
    }


def _decision(*, source: str = "policy-bundle", owner: str = _RULE_ID, action: str = "review") -> dict[str, object]:
    return {"decision": {"action": action, "owner": owner, "source": source, "scope": "global"}}


class _Lookups:
    def __init__(self, result: dict[str, object] | Exception) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def __call__(self, harness: str, artifact_id: str | None, **kwargs: object) -> dict[str, object]:
        self.calls.append({"harness": harness, "artifact_id": artifact_id, **kwargs})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    bundle: dict[str, object] | None,
    lookup: dict[str, object] | Exception,
) -> tuple[GuardStore, dict[str, object], _Lookups]:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("req-attribution"))
    row = store.get_raw_approval_request_snapshot("req-attribution")
    assert isinstance(row, dict)
    lookups = _Lookups(lookup)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: bundle)
    monkeypatch.setattr(store, "resolve_policy_decision_lookup", lookups)
    return store, row, lookups


def _created(row: dict[str, object]) -> datetime:
    return datetime.fromisoformat(str(row["created_at"]))


def test_claim_names_the_cloud_rule_that_queued_the_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=_decision())
    bundle = _bundle(issued_at=_created(row) - timedelta(minutes=5))
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: bundle)

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert claim["policyRuleId"] == _RULE_ID
    assert claim["policyBundleVersion"] == "policy-1730000000000"
    assert claim["claimHash"] == compute_local_review_request_claim_hash(claim)
    # The lookup replays the request's own identity without consuming anything.
    assert lookups.calls == [
        {
            "harness": "codex",
            "artifact_id": row["artifact_id"],
            "artifact_hash": row["artifact_hash"],
            "workspace": row["workspace"],
            "publisher": None,
            "now": row["created_at"],
            "consume_one_shot": False,
        }
    ]


def test_claim_keeps_its_recorded_rule_after_policy_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=_decision())
    issued = _created(row) - timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=issued))
    oauth = _oauth_metadata(store)
    first = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)

    # A newer bundle and a local approval must not change an open request's claim.
    monkeypatch.setattr(
        attribution_module,
        "validated_synced_policy_bundle",
        lambda _store: _bundle(issued_at=issued, version="policy-1730000099999"),
    )
    lookups.result = _decision(source="approval-gate", owner="local", action="allow")
    second = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)

    assert second["claimHash"] == first["claimHash"]
    assert second["policyBundleVersion"] == "policy-1730000000000"
    assert len(lookups.calls) == 1


@pytest.mark.parametrize(
    "decision",
    [
        _decision(source="approval-gate", owner="local"),
        _decision(action="block"),
        _decision(owner="rule-not-in-bundle"),
        {"decision": None},
    ],
)
def test_claim_names_no_rule_unless_a_published_review_rule_decided(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decision: dict[str, object]
) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=decision)
    issued = _created(row) - timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=issued))
    oauth = _oauth_metadata(store)

    first = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    lookups.result = _decision()
    second = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)

    assert "policyRuleId" not in first
    assert second["claimHash"] == first["claimHash"]


def test_bundle_published_after_the_request_is_not_credited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=_decision())
    later = _created(row) + timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=later))

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert "policyRuleId" not in claim
    assert lookups.calls == []


def test_request_cloud_already_received_keeps_its_original_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=_decision())
    issued = _created(row) - timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=issued))
    with store._connect() as connection:
        updated = connection.execute(
            "update guard_review_outbox_events set attempt_count = 1 where local_request_id = ?",
            ("req-attribution",),
        ).rowcount
    assert updated > 0

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert "policyRuleId" not in claim
    assert lookups.calls == []


def test_failed_lookup_records_nothing_so_the_next_claim_can_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=RuntimeError("resident unavailable"))
    issued = _created(row) - timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=issued))
    oauth = _oauth_metadata(store)

    first = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    lookups.result = _decision()
    second = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)

    assert "policyRuleId" not in first
    assert second["policyRuleId"] == _RULE_ID
    assert datetime.now(timezone.utc) >= _created(row)
