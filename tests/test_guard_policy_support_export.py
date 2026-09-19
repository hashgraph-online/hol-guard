"""HGP-188: privacy-safe local policy support export."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.policy_support_export import build_policy_support_export
from tests.guard_exact_cloud_review_support import connected_exact_review_store

_SECRET_MARKERS = ("refresh-token", "dpop_private_key", "access_token", "BEGIN PRIVATE KEY", "canary-secret")


def test_support_export_classifies_failures_without_secrets(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    export = build_policy_support_export(store, now="2026-09-17T12:00:00+00:00")
    dumped = repr(export)
    assert export["kind"] == "hol-guard-policy-support-export.v1"
    assert set(export["failure_classes"]) >= {
        "auth",
        "invalid_policy",
        "wrong_target",
        "runtime_publication",
        "continuation",
    }
    assert export["cloud_review"]["personal_consent_required_for_managed_admin_review"] is False
    assert export["error"]["next_action"]
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
    assert export["cloud_review"]["diagnostics"]["worker"]["exact_review_route_error"] is None
    assert export["policy"]["last_error"] == {"reason": "unclassified_failure", "retained_last_good": False}
    assert export["sync"]["telemetry_degradation"] == {"reason": "telemetry_degradation"}


def test_saved_bundle_metadata_never_claims_policy_applied(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    now = "2026-09-17T12:00:00+00:00"
    store.set_sync_payload("policy_bundle_last_good", {"bundleHash": "unverified", "revision": 1}, now)
    export = build_policy_support_export(store, now=now)
    assert export["policy"] == {"applied": False}


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
