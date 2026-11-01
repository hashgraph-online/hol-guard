"""Review claims name the published Cloud rule that queued them, and keep it."""

from __future__ import annotations

from datetime import datetime, timedelta
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


@pytest.mark.parametrize(
    "sent",
    [
        # An acknowledged event is deleted from the outbox.
        "delete from guard_review_outbox_events where local_request_id = ?",
        "update guard_review_outbox_events set attempt_count = 1 where local_request_id = ?",
        "update guard_review_outbox_events set acknowledged_at = '2026-01-01T00:00:00Z' where local_request_id = ?",
    ],
    ids=["acknowledged-and-pruned", "upload-attempted", "acknowledged"],
)
def test_request_that_may_have_reached_cloud_keeps_a_claim_without_a_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sent: str
) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=_decision())
    issued = _created(row) - timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=issued))
    with store._connect() as connection:
        assert connection.execute(sent, ("req-attribution",)).rowcount > 0
    oauth = _oauth_metadata(store)

    first = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    second = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)

    assert "policyRuleId" not in first
    assert second["claimHash"] == first["claimHash"]
    assert lookups.calls == []


def test_failed_lookup_records_no_rule_so_the_claim_never_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store, row, lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=RuntimeError("resident unavailable"))
    issued = _created(row) - timedelta(minutes=5)
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: _bundle(issued_at=issued))
    oauth = _oauth_metadata(store)

    with caplog.at_level("WARNING", logger=attribution_module.__name__):
        first = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)
    # The first claim may already have reached Cloud, so a later answer must not change it.
    lookups.result = _decision()
    second = build_local_review_request_claim(request_row=row, oauth=oauth, store=store)

    assert "policyRuleId" not in first
    assert second["claimHash"] == first["claimHash"]
    assert len(lookups.calls) == 1
    assert "RuntimeError" in caplog.text


def test_claim_names_the_rule_from_a_signed_bundle_through_the_native_lookup(tmp_path: Path) -> None:
    """No fakes: a signed review rule reaches the store and the real lookup credits it."""

    from dataclasses import replace

    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
    from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
    from tests.policy_store_support import replace_remote_policies, resolve_policy

    store = connected_exact_review_store(tmp_path)
    rules: list[dict[str, object]] = [
        {
            "ruleId": "mcp-review",
            "action": "review",
            "reason": "Review MCP server calls.",
            "matcherFamilies": ["mcp"],
            "scope": {
                "agents": [],
                "devices": [],
                "ecosystems": [],
                "environments": ["development"],
                "harnesses": ["codex"],
                "locations": [],
            },
        }
    ]
    bundle: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-01-01.1",
        "issuedAt": "2026-01-01T00:00:00Z",
        "expiresAt": None,
        "verifier": {},
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "block",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "block",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": rules,
        "acknowledgements": [],
    }
    decisions = guard_runner_module._build_policy_bundle_decisions(
        bundle,
        device_id=guard_runner_module._guard_device_metadata(store)[0],
        device_name="Test device",
    )
    replace_remote_policies(store, decisions, "2026-01-01T00:00:01+00:00", remote_write_authorized=True)
    store.set_sync_payload(
        "policy_bundle_keyring", policy_bundle_test_keyring(workspace_id="workspace-1"), "2026-01-01T00:00:00Z"
    )
    store.set_sync_payload(
        "policy_bundle", sign_policy_bundle(bundle, workspace_id="workspace-1"), "2026-01-01T00:00:00Z"
    )
    assert resolve_policy(store, "codex", "codex:project:mcp:shell", "hash") == "review"

    request = replace(review_request("req-native-rule"), artifact_id="codex:project:mcp:shell", policy_action="review")
    add_review_request(store, request)
    row = store.get_raw_approval_request_snapshot("req-native-rule")
    assert isinstance(row, dict)

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert claim["policyRuleId"] == "mcp-review"
    assert claim["policyBundleVersion"] == "policy-2026-01-01.1"


def _v2_bundle(*, issued_at: datetime, revision: int = 7) -> dict[str, object]:
    return {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": revision,
        "issuedAt": issued_at.isoformat(),
        "payload": {
            "metadata": {"id": "policy-workspace", "revision": revision},
            "spec": {"rules": [{"id": _RULE_ID, "effect": "review"}, {"id": "allow-docs", "effect": "allow"}]},
        },
    }


def test_claim_names_the_v2_document_revision_for_a_canonical_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, row, _lookups = _setup(
        tmp_path, monkeypatch, bundle=None, lookup=_decision(source="policy-bundle-canonical")
    )
    bundle = _v2_bundle(issued_at=_created(row) - timedelta(minutes=5))
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: bundle)

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert claim["policyRuleId"] == _RULE_ID
    assert claim["policyBundleVersion"] == "guard-policy-bundle.v2:7"


@pytest.mark.parametrize(
    ("source", "owner"),
    [
        # A v1 row cannot borrow a v2 bundle's identity, nor a local row.
        ("policy-bundle", _RULE_ID),
        ("local", _RULE_ID),
        # A rule the delivered document never carried.
        ("policy-bundle-canonical", "someone-else"),
    ],
)
def test_v2_attribution_needs_a_canonical_row_for_a_delivered_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, owner: str
) -> None:
    store, row, _lookups = _setup(tmp_path, monkeypatch, bundle=None, lookup=_decision(source=source, owner=owner))
    bundle = _v2_bundle(issued_at=_created(row) - timedelta(minutes=5))
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: bundle)

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert "policyRuleId" not in claim
    assert "policyBundleVersion" not in claim


def test_a_canonical_row_is_not_attributed_against_a_v1_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, row, _lookups = _setup(
        tmp_path, monkeypatch, bundle=None, lookup=_decision(source="policy-bundle-canonical")
    )
    bundle = _bundle(issued_at=_created(row) - timedelta(minutes=5))
    monkeypatch.setattr(attribution_module, "validated_synced_policy_bundle", lambda _store: bundle)

    claim = build_local_review_request_claim(request_row=row, oauth=_oauth_metadata(store), store=store)

    assert "policyRuleId" not in claim
