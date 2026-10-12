"""Recorded parity and fail-closed behaviour for the native Guard Cloud sync owner.

``fixtures/runner_sync_authority/vectors.json`` was recorded from the retired
Python helpers in ``guard/runtime/runner.py`` before they were deleted; the same
file is replayed by the Rust unit tests, so a divergence here means the resident
changed behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.policy_bundle_parser import POLICY_BUNDLE_RULE_MATCHER_FAMILIES
from codex_plugin_scanner.guard.runtime import runner_native_sync as sync

_VECTORS = Path(__file__).parent / "fixtures" / "runner_sync_authority" / "vectors.json"


@pytest.fixture(autouse=True)
def _fresh_url_cache() -> None:
    sync._derived_url.cache_clear()


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(_VECTORS.read_text(encoding="utf-8"))
    assert document["version"] == 1
    return document["vectors"]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_recorded_python_vectors_match_the_resident() -> None:
    vectors = _vectors()
    assert len(vectors) > 800
    mismatches = [
        f"{vector['kind']} / {vector['name']}"
        for vector in vectors
        if native_runner_authority(vector["kind"], vector["args"]) != vector["expected"]
    ]
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_typed_adapters_return_the_owner_answer() -> None:
    assert sync.guard_events_sync_url("https://hol.org/guard/receipts/sync") == "https://hol.org/api/v1/guard/events"
    assert sync.pain_signal_sync_url("https://hol.org/api/v1") == "https://hol.org/api/v1/signals/pain"
    events = [
        {
            "event_name": "install_time_block",
            "occurred_at": "2026-01-01T00:00:00Z",
            "payload": {"artifact_id": "a", "artifact_name": "A", "reason": "bad", "unrelated": "x" * 10},
        }
    ]
    items, carried = sync.pain_signal_batch(events, {})
    assert [item["signalId"] for item in items] == ["install_time_block:unknown:a"]
    assert carried == {}
    metrics, digest = sync.value_metrics(events, "2026-01-02T00:00:00Z")
    assert metrics["installs_stopped_before_execution"]["value"] == 1
    assert digest["generated_at"] == "2026-01-02T00:00:00Z"
    older = {"issuedAt": "2026-01-01T00:00:00Z", "bundleVersion": "1", "bundleHash": "old"}
    newer = {"issuedAt": "2026-02-01T00:00:00Z", "bundleVersion": "2", "bundleHash": "new"}
    assert sync.policy_bundle_downgrade_reference([older, None, newer], None) is newer
    assert sync.policy_bundle_downgrade_reference([None, "x"], None) is None
    assert sync.completed_guard_event_ids({"statuses": [{"status": "accepted", "eventId": "e"}]}) == ["e"]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_rollout_reads_the_environment_value_it_is_given(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(sync.POLICY_CANONICAL_ENFORCEMENT_ENV, "canonical")
    assert sync.canonical_policy_enforcement_enabled(device_id="d", workspace_id=None) is True
    monkeypatch.setenv(sync.POLICY_CANONICAL_ENFORCEMENT_ENV, "off")
    assert sync.canonical_policy_enforcement_enabled(device_id="d", workspace_id=None) is False
    monkeypatch.delenv(sync.POLICY_CANONICAL_ENFORCEMENT_ENV)
    assert sync.canonical_policy_enforcement_enabled(device_id="d", workspace_id="w") is False


@pytest.mark.usefixtures("native_approval_reuse_runtime")
@pytest.mark.parametrize(
    "kind",
    [
        "sync_url",
        "pain_signal_batch",
        "value_metrics",
        "completed_event_ids",
        "canonical_rollout",
        "downgrade_reference",
        "policy_simulation",
    ],
)
def test_malformed_arguments_fail_closed(kind: str) -> None:
    with pytest.raises(NativeRunnerAuthorityError):
        native_runner_authority(kind, {"unexpected": 1})


def test_native_unavailable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(kind: str, args: object, guard_home: object = None) -> dict[str, Any]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(sync, "native_runner_authority", refuse)
    with pytest.raises(NativeRunnerAuthorityError):
        sync.normalized_receipts_sync_url("https://hol.org/guard/receipts/sync")
    with pytest.raises(NativeRunnerAuthorityError):
        sync.canonical_policy_enforcement_enabled(device_id="d", workspace_id=None)


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_simulation_covers_every_parser_matcher_family() -> None:
    """The resident's family list must not drift from the bundle parser's."""

    families = sorted(POLICY_BUNDLE_RULE_MATCHER_FAMILIES)
    receipts = [
        {
            "receipt_id": f"r-{family}",
            "artifact_id": f"guard:{family}:x",
            "harness": "codex",
            "policy_decision": "allow",
        }
        for family in families
    ]
    result = sync.policy_simulation(receipts, [], bundle_version="1", bundle_hash="h", now="2026-04-11T00:00:00Z")
    assert sorted(match["matcher_family"] for match in result["matches"]) == families


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_url_derivation_is_reused_for_the_same_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://hol.org/guard/receipts/sync"
    first = sync.normalized_runtime_sessions_sync_url(url)

    def refuse(kind: str, args: object, guard_home: object = None) -> dict[str, Any]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(sync, "native_runner_authority", refuse)
    assert sync.normalized_runtime_sessions_sync_url(url) == first
