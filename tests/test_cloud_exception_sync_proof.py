"""Cross-repo Cloud exception sync proof (HGLP136-HGLP141)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cloud_exceptions import (
    build_cloud_exceptions_from_policy_bundle,
    list_active_cloud_exceptions,
)
from codex_plugin_scanner.guard.policy_bundle_parser import validated_policy_bundle_payload
from codex_plugin_scanner.guard.runtime.runner import _persist_cloud_exceptions
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import (
    build_cloud_exception_bundle_entry,
    build_cloud_exception_policy_bundle,
)
from tests.test_policy_bundle_parser import computed_policy_bundle_hash


def test_hglp136_fixture_is_code_generated_not_static_ui_copy() -> None:
    bundle = build_cloud_exception_policy_bundle()
    assert isinstance(bundle.get("cloudExceptions"), list)
    assert bundle["cloudExceptions"][0]["exceptionId"] == "artifact:codex:sync-proof"


def test_hglp137_local_daemon_accepts_valid_exception_bundle(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    bundle = build_cloud_exception_policy_bundle()
    validated, reason = validated_policy_bundle_payload(bundle)
    assert reason is None
    assert validated is not None
    _persist_cloud_exceptions(store, policy_bundle=validated, now="2026-06-14T12:00:00+00:00")
    listed = store.list_cloud_exceptions()
    assert len(listed) == 1
    assert listed[0]["id"] == "artifact:codex:sync-proof"


def test_hglp138_local_daemon_rejects_tampered_exception_bundle(tmp_path: Path) -> None:
    bundle = build_cloud_exception_policy_bundle()
    bundle["bundleHash"] = "sha256:tampered"
    validated, reason = validated_policy_bundle_payload(bundle)
    assert validated is None
    assert reason == "bundle_hash_mismatch"


def test_hglp139_expired_cloud_exception_is_not_active_after_bundle_load() -> None:
    bundle = build_cloud_exception_policy_bundle(
        cloud_exceptions=[
            build_cloud_exception_bundle_entry(
                exception_id="artifact:codex:expired",
                expires_at="2020-01-01T00:00:00+00:00",
            )
        ]
    )
    items = build_cloud_exceptions_from_policy_bundle(bundle, device_id="device-sync-proof")
    active = list_active_cloud_exceptions(items, now="2026-06-14T12:00:00+00:00")
    assert active == []


def test_hglp140_wrong_workspace_bundle_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "guard-live-token",
        "2026-06-14T12:00:00+00:00",
        workspace_id="workspace-a",
    )
    bundle = build_cloud_exception_policy_bundle(workspace_id="workspace-b")
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"accepted": 0, "rejected": 0, "statuses": []})
        return _Response(
            {
                "syncedAt": "2026-06-14T12:00:01+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_last_error") == {"reason": "wrong_workspace"}


def test_hglp141_bundle_ack_metadata_is_available_for_sync_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "guard-live-token",
        "2026-06-14T12:00:00+00:00",
    )
    bundle = build_cloud_exception_policy_bundle()
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    requests: list[dict[str, object]] = []

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"accepted": 0, "rejected": 0, "statuses": []})
        body = json.loads(request.data.decode("utf-8"))
        requests.append(body)
        return _Response(
            {
                "syncedAt": f"2026-06-14T12:00:0{len(requests)}+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)
    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is not None
    assert "policyBundleAcknowledgement" in requests[1]["syncContext"]
