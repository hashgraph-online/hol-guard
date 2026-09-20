"""HGP-188: privacy-safe local policy support export."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.policy_support_export import build_policy_support_export
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import connected_exact_review_store, review_request

_SECRET_MARKERS = ("refresh-token", "dpop_private_key", "access_token", "BEGIN PRIVATE KEY", "canary-secret")


def _section(export: dict[str, object], *keys: str) -> dict[str, object]:
    value: object = export
    for key in keys:
        assert isinstance(value, dict)
        value = value[key]
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def test_support_export_classifies_failures_without_secrets(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    export = build_policy_support_export(store, now="2026-09-17T12:00:00+00:00")
    dumped = repr(export)
    assert export["kind"] == "hol-guard-policy-support-export.v1"
    assert set(_section(export, "failure_classes")) >= {
        "auth",
        "invalid_policy",
        "wrong_target",
        "runtime_publication",
        "continuation",
    }
    assert _section(export, "cloud_review")["personal_consent_required_for_managed_admin_review"] is False
    assert _section(export, "error")["next_action"]
    assert not any(marker in dumped for marker in _SECRET_MARKERS)


def test_support_export_omits_arbitrary_diagnostic_and_telemetry_details(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    secret = "opaque-private-value-9fd7"
    now = "2026-09-17T12:00:00+00:00"
    store.set_sync_payload(
        "guard_command_queue_state",
        {
            "state": "idle",
            "exact_review_route_error": f"upstream failure: {secret}",
        },
        now,
    )
    store.set_sync_payload(
        "sync_summary",
        {
            "telemetry_degradation": {"message": secret, "retryable": True},
        },
        now,
    )
    store.set_sync_payload("policy_bundle_last_error", {"reason": secret}, now)
    export = build_policy_support_export(store, now=now)
    assert secret not in repr(export)
    assert _section(export, "cloud_review", "diagnostics", "worker")["exact_review_route_error"] is None
    assert _section(export, "policy")["last_error"] == {"reason": "unclassified_failure", "retained_last_good": False}
    assert _section(export, "sync")["telemetry_degradation"] == {"reason": "telemetry_degradation"}


def test_saved_bundle_metadata_never_claims_policy_applied(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    now = "2026-09-17T12:00:00+00:00"
    store.set_sync_payload("policy_bundle_last_good", {"bundleHash": "unverified", "revision": 1}, now)
    export = build_policy_support_export(store, now=now)
    assert _section(export, "policy") == {"applied": False}


def test_support_export_cli_uses_passive_status_path(tmp_path: Path, capsys) -> None:
    import json

    from codex_plugin_scanner.cli import main

    store = connected_exact_review_store(tmp_path)
    with store._connect() as connection:
        connection.execute("pragma wal_checkpoint(truncate)")
    before = {path.name: path.read_bytes() for path in store.guard_home.iterdir() if path.is_file()}
    assert (
        main(["guard", "cloud-review", "status", "--guard-home", str(store.guard_home), "--support-export", "--json"])
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "hol-guard-policy-support-export.v1"
    after = {path.name: path.read_bytes() for path in store.guard_home.iterdir() if path.is_file()}
    assert {key: value for key, value in after.items() if not key.endswith(("-wal", "-shm"))} == {
        key: value for key, value in before.items() if not key.endswith(("-wal", "-shm"))
    }


def _record_continuation(store: GuardStore, *, status: str = "failed", evidence_id: str = "failure-evidence") -> None:
    now = "2026-09-17T12:00:00+00:00"
    request_id = "support-continuation-request"
    if store.get_approval_request(request_id) is None:
        store.add_approval_request(review_request(request_id), now)
    assert store.finalize_continuation_attempt(
        request_id=request_id,
        offer_hash=evidence_id,
        action="allow_once",
        claim_id=None,
        evidence_id=evidence_id,
        terminal=True,
        resume_seed={"harness": "codex", "strategy": "session-resume", "supported": True},
        resume_update={
            "status": status,
            "attempt_count": 1,
            "last_error": "opaque-private-continuation-detail-9fd7",
            "continuation_status": status,
            "continuation_capability": "session-resume",
            "continuation_reason": "opaque-private-continuation-detail-9fd7",
            "continuation_completed_at": now,
            "continuation_evidence": [{"correlationId": "gcr_12345678-1234-4234-8234-123456789abc"}],
        },
        operation_update=None,
        events=[],
        now=now,
    )


def test_support_export_cli_classifies_retained_bound_continuation_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from codex_plugin_scanner.cli import main

    store = connected_exact_review_store(tmp_path)
    _record_continuation(store)
    with store._connect() as connection:
        connection.execute("pragma wal_checkpoint(truncate)")
    before = {path.name: path.read_bytes() for path in store.guard_home.iterdir() if path.is_file()}
    assert (
        main(["guard", "cloud-review", "status", "--guard-home", str(store.guard_home), "--support-export", "--json"])
        == 0
    )
    text = capsys.readouterr().out
    export = json.loads(text)
    assert _section(export, "failure_classes")["continuation"] is True
    assert _section(export, "cloud_review")["delivery_state"] == "unknown"
    assert _section(export, "cloud_review", "continuation_evidence") == {
        "scope": "retained_current_connection_events",
        "failure_observed": True,
        "runtime_state": "unknown",
    }
    assert "opaque-private-continuation-detail-9fd7" not in text
    assert not any(marker in text for marker in _SECRET_MARKERS)
    after = {path.name: path.read_bytes() for path in store.guard_home.iterdir() if path.is_file()}
    assert {k: v for k, v in after.items() if not k.endswith(("-wal", "-shm"))} == {
        k: v for k, v in before.items() if not k.endswith(("-wal", "-shm"))
    }


@pytest.mark.parametrize(
    "field", ["oauth_source", "oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id"]
)
def test_support_export_does_not_attribute_foreign_or_stale_bound_failure(tmp_path: Path, field: str) -> None:
    import json

    from codex_plugin_scanner.guard.review_event_integrity import review_event_payload_digest
    from codex_plugin_scanner.guard.runtime.review_event_delivery import decode_stored_review_event

    store = connected_exact_review_store(tmp_path)
    _record_continuation(store)
    # Retain a structurally valid old/foreign envelope, including its own correct digest.
    with store._connect() as connection:
        row = dict(
            connection.execute(
                "select * from guard_review_outbox_events where event_type = 'review.continuation.failed'"
            ).fetchone()
        )
        row[field] = "other-identity"
        if field == "oauth_source":
            payload = json.loads(row["payload_json"])
            payload["oauthSource"] = row[field]
            payload["requestSnapshot"]["oauth_source"] = row[field]
            row["payload_json"] = json.dumps(payload)
        binding = {
            key: row[key]
            for key in ("oauth_source", "oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
        }
        digest = review_event_payload_digest(row["payload_json"], **binding)
        row["payload_hash"] = digest
        assert decode_stored_review_event(row).continuation_result is not None
        connection.execute(
            f"update guard_review_outbox_events set {field} = ?, payload_hash = ?, payload_json = ? "
            "where stream_sequence = ?",
            (row[field], digest, row["payload_json"], row["stream_sequence"]),
        )
    export = build_policy_support_export(store, now="2026-09-17T12:01:00+00:00")
    assert _section(export, "failure_classes")["continuation"] is False
    assert _section(export, "cloud_review", "continuation_evidence")["runtime_state"] == "unknown"
    assert "other-identity" not in repr(export)


@pytest.mark.parametrize(
    "status", ["resumed", "already_resumed", "manual_retry_required", "blocked_not_resumed", "unsupported"]
)
def test_support_export_does_not_treat_nonfailure_outcomes_as_continuation_failure(tmp_path: Path, status: str) -> None:
    store = connected_exact_review_store(tmp_path)
    _record_continuation(store, status=status)
    export = build_policy_support_export(store, now="2026-09-17T12:01:00+00:00")
    assert _section(export, "failure_classes")["continuation"] is False


def test_support_export_drops_superseded_failure_without_claiming_runtime_health(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    _record_continuation(store)
    before = build_policy_support_export(store, now="2026-09-17T12:01:00+00:00")
    assert _section(before, "failure_classes")["continuation"] is True
    _record_continuation(store, status="resumed", evidence_id="success-evidence")
    export = build_policy_support_export(store, now="2026-09-17T12:01:00+00:00")
    assert _section(export, "failure_classes")["continuation"] is False
    assert _section(export, "cloud_review")["delivery_state"] == "unknown"


@pytest.mark.parametrize(
    "invalid", ["digest", "quarantined", "future", "compacted", "disconnected", "unavailable_credentials"]
)
def test_support_export_keeps_unavailable_continuation_evidence_unknown(tmp_path: Path, invalid: str) -> None:
    store = connected_exact_review_store(tmp_path)
    _record_continuation(store)
    with store._connect() as connection:
        if invalid == "digest":
            connection.execute("update guard_review_outbox_events set payload_hash = 'invalid'")
        elif invalid == "quarantined":
            connection.execute("update guard_review_outbox_events set binding_status = 'quarantined'")
        elif invalid == "disconnected":
            connection.execute("delete from sync_state where state_key = 'oauth_local_credentials'")
        elif invalid == "unavailable_credentials":
            connection.execute(
                "update sync_state set payload_json = json_set(payload_json, '$.credentials_sha256', ?) "
                "where state_key = 'oauth_local_credentials'",
                ("0" * 64,),
            )
    if invalid == "compacted":
        binding = store.get_review_event_oauth_binding()
        assert binding is not None
        delivery = {key: value for key, value in binding.items() if key != "oauth_source"}
        events = store.list_ready_review_events(
            now="2026-09-17T12:01:00+00:00",
            limit=10,
            workspace_id=binding["workspace_id"],
            oauth_subject_hash=binding["oauth_subject_hash"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
        sequences: list[int] = []
        for row in events:
            sequence = row["sequence"]
            assert isinstance(sequence, int)
            sequences.append(sequence)
        assert store.acknowledge_review_events(sequences, **delivery) == len(events)
    observed = "2026-09-17T11:59:00+00:00" if invalid == "future" else "2026-09-17T12:01:00+00:00"
    export = build_policy_support_export(store, now=observed)
    assert _section(export, "failure_classes")["continuation"] is False
    assert _section(export, "cloud_review", "continuation_evidence") == {
        "scope": "retained_current_connection_events",
        "failure_observed": False,
        "runtime_state": "unknown",
    }
