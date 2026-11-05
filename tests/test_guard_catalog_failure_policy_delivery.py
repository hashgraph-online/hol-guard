"""A failed Extension catalog step must not keep the policy bundle from a device.

The policy bundle arrives with the receipts sync, which runs after the runtime
session sync that carries the catalog step. Both the daemon's periodic sync and
`hol-guard sync` go through `sync_local_guard_cloud_proof`, so a catalog error
raised there used to stop every later sync before policy was fetched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore

_AUTH = {"sync_url": "https://hol.org/api/guard/receipts/sync"}
_SESSION = {
    "sessionId": "runtime-session-1",
    "harness": "hol-guard",
    "surface": "cli",
    "workspace": "local-machine",
    "deviceId": "device-1",
}


def _rejected_catalog(**_kwargs: object) -> dict[str, object]:
    raise ValueError("Native complete catalog producer rejected metadata")


def _patch_runtime_session_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "_cloud_runtime_session_payload", lambda _store, _session: dict(_SESSION))
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        runner,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: {"generatedAt": "2026-11-05T12:00:00+00:00", "items": [{"sessionId": "runtime-session-1"}]},
    )
    monkeypatch.setattr(runner, "_guard_events_endpoint_unavailable_recently", lambda _store: True)
    monkeypatch.setattr(runner, "_sync_extension_catalog_from_runtime_handshake", _rejected_catalog)


def test_runtime_session_sync_still_raises_a_catalog_failure_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_runtime_session_transport(monkeypatch)

    with pytest.raises(ValueError, match="rejected metadata"):
        runner.sync_runtime_session(GuardStore(tmp_path / "guard-home"), session={}, auth_context=_AUTH)


def test_runtime_session_sync_hands_a_catalog_failure_to_the_caller(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_runtime_session_transport(monkeypatch)
    failures: list[Exception] = []

    summary = runner.sync_runtime_session(
        GuardStore(tmp_path / "guard-home"), session={}, auth_context=_AUTH, catalog_failures=failures
    )

    assert [str(error) for error in failures] == ["Native complete catalog producer rejected metadata"]
    assert summary["runtime_session_id"] == "runtime-session-1"
    assert summary["extension_catalog_sync_status"] == "failed"
    assert summary["extension_catalog_sync_reason"] == "catalog_sync_failed"


def test_cloud_proof_sync_delivers_policy_before_reporting_a_catalog_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _patch_runtime_session_transport(monkeypatch)
    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", lambda _store: _AUTH)
    receipts_calls: list[dict[str, object]] = []

    def fake_sync_receipts(current_store: GuardStore, **kwargs: object) -> dict[str, object]:
        assert current_store is store
        receipts_calls.append(kwargs)
        return {"synced_at": "2026-11-05T12:00:05+00:00", "receipts_stored": 0}

    monkeypatch.setattr(runner, "sync_receipts", fake_sync_receipts)

    with pytest.raises(ValueError, match="rejected metadata"):
        runner.sync_local_guard_cloud_proof(store)

    assert len(receipts_calls) == 1
    assert receipts_calls[0]["auth_context"] is _AUTH


def test_runtime_session_sync_keeps_the_previous_summary_when_the_catalog_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    previous = {"runtime_session_id": "runtime-session-0", "runtime_credential_id": "credential-0"}
    store.set_sync_payload("runtime_session_summary", previous, "2026-11-05T11:00:00+00:00")
    _patch_runtime_session_transport(monkeypatch)

    runner.sync_runtime_session(store, session={}, auth_context=_AUTH, catalog_failures=[])

    assert store.get_sync_payload("runtime_session_summary") == previous


def test_clearing_policy_authority_stores_the_failed_acknowledgement_in_the_same_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_ack", {"bundleHash": "sha256:a", "status": "synced"}, "2026-11-05T11:00:00Z")
    # A concurrent sync activates bundle B before this clear runs; the failure must name B.
    store.set_sync_payload("policy_bundle_ack", {"bundleHash": "sha256:b", "status": "synced"}, "2026-11-05T11:30:00Z")
    seen: list[object] = []

    def build_failed(stored: object) -> dict[str, object]:
        seen.append(stored)
        assert isinstance(stored, dict)
        return {"bundleHash": stored["bundleHash"], "status": "failed"}

    store.clear_policy_bundle_authority(
        "2026-11-05T12:00:00Z",
        policy_bundle_last_error={"reason": "wrong_workspace"},
        policy_bundle_ack=build_failed,
    )

    assert seen == [{"bundleHash": "sha256:b", "status": "synced"}]
    assert store.get_sync_payload("policy_bundle_ack") == {"bundleHash": "sha256:b", "status": "failed"}
    assert store.get_sync_payload("policy_bundle_last_error") == {"reason": "wrong_workspace"}

    store.clear_policy_bundle_authority("2026-11-05T12:05:00Z", policy_bundle_last_error={})

    assert store.get_sync_payload("policy_bundle_ack") is None
