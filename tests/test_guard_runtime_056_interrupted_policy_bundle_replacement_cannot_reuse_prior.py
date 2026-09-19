"""Runtime regression tests: interrupted policy bundle replacement cannot reuse prior."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from typing import ClassVar

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    HTTPServer,
    guard_runner_module,
    json,
    policy_bundle_test_keyring,
    sign_policy_bundle,
    stub_authenticated_urlopen,
    threading,
)
from tests.guard_runtime_test_support import (
    _cache_signed_test_policy_bundle,
    _seed_guard_cloud,
    _signed_test_policy_bundle,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_interrupted_policy_bundle_replacement_cannot_reuse_prior_materialized_allow(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    old_rule = {
        "ruleId": "old-package-allow",
        "action": "allow",
        "reason": "Old signed package allow.",
        "artifactType": "package_request",
        "matcherFamilies": ["package-request"],
        "scope": {"harnesses": ["codex"], "ecosystems": []},
    }
    _cache_signed_test_policy_bundle(store, [old_rule])
    device_metadata = store.get_device_metadata()
    old_bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(old_bundle, dict)
    old_decisions = guard_runner_module._build_policy_bundle_decisions(
        old_bundle,
        device_id=device_metadata["installation_id"],
        device_name=device_metadata["device_label"],
    )
    store.replace_remote_policies(
        old_decisions,
        "2026-01-01T00:00:00Z",
        remote_write_authorized=True,
    )
    artifact_id = "codex:project:package-request:test"
    assert store.resolve_policy("codex", artifact_id, "sha256:test") == "allow"

    # Both sync paths persist the newly verified bundle before replacing its
    # materialized rows. Simulate a process interruption at exactly that point.
    replacement_bundle = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2026-01-02.1",
        issued_at="2026-01-02T00:00:00Z",
    )
    store.set_sync_payload("policy_bundle", replacement_bundle, "2026-01-02T00:00:00Z")
    store.set_sync_payload("policy_bundle_last_good", replacement_bundle, "2026-01-02T00:00:00Z")

    assert store.resolve_policy("codex", artifact_id, "sha256:test") is None


def test_policy_bundle_downgrade_check_normalizes_mixed_timezone_formats():
    assert (
        guard_runner_module._policy_bundle_is_version_downgrade(
            {"issuedAt": "2026-06-05T13:30:00+00:00"},
            {"issuedAt": "2026-06-05T13:29:00"},
        )
        is True
    )


def test_policy_bundle_v2_downgrade_check_uses_monotonic_bundle_version():
    current = {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 8,
        "bundleHash": "a" * 64,
        "issuedAt": "2026-06-05T13:30:00Z",
    }

    assert guard_runner_module._policy_bundle_is_version_downgrade(
        current,
        {
            "contractVersion": "guard-policy-bundle.v2",
            "bundleVersion": 7,
            "bundleHash": "b" * 64,
            "issuedAt": "2026-06-05T13:31:00Z",
        },
    )
    assert guard_runner_module._policy_bundle_is_version_downgrade(
        current,
        {
            "contractVersion": "guard-policy-bundle.v2",
            "bundleVersion": 8,
            "bundleHash": "b" * 64,
            "issuedAt": "2026-06-05T13:31:00Z",
        },
    )
    assert (
        guard_runner_module._policy_bundle_is_version_downgrade(
            current,
            {
                "contractVersion": "guard-policy-bundle.v2",
                "bundleVersion": 9,
                "bundleHash": "b" * 64,
                "issuedAt": "2026-06-05T13:31:00Z",
            },
        )
        is False
    )


def test_sync_receipts_uploads_policy_bundle_acknowledgement(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-06-05T13:29:00Z")
    requests: list[dict[str, object]] = []
    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-06-05.3",
        "bundleHash": "",
        "issuedAt": "2026-06-05T13:30:00+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [],
        "acknowledgements": [],
    }
    bundle = sign_policy_bundle(bundle)

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
                "syncedAt": f"2026-06-05T13:30:0{len(requests)}+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)
    guard_runner_module.sync_receipts(store)

    assert requests[1]["syncContext"]["policyBundleAcknowledgement"] == {
        "appliedAt": "2026-06-05T13:30:01+00:00",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": "policy-2026-06-05.3",
        "deviceId": guard_runner_module._guard_device_metadata(store)[0],
        "deviceName": guard_runner_module._guard_device_metadata(store)[1],
        "status": "synced",
    }


def test_sync_receipts_uploads_policy_bundle_acknowledgement_to_sync_route(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-06-05.4",
        "bundleHash": "",
        "issuedAt": "2026-06-05T13:30:00+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [],
        "acknowledgements": [],
    }
    bundle = sign_policy_bundle(bundle)

    class _AckSyncHandler(BaseHTTPRequestHandler):
        requests: ClassVar[list[dict[str, object]]] = []

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            _AckSyncHandler.requests.append(payload)
            response_payload = {
                "syncedAt": f"2026-06-05T13:30:0{len(_AckSyncHandler.requests)}+00:00",
                "receiptsStored": len(payload.get("receipts", [])),
                "policyBundle": bundle,
            }
            encoded = json.dumps(response_payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format_string, *args):
            del format_string, args
            return

    server = HTTPServer(("127.0.0.1", 0), _AckSyncHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _seed_guard_cloud(
            store,
            workspace_id="workspace-1",
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="guard-live-token",
        )
        store.set_sync_payload(
            "policy_bundle_keyring",
            policy_bundle_test_keyring(),
            "2026-06-05T13:29:00Z",
        )
        monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

        guard_runner_module.sync_receipts(store)
        guard_runner_module.sync_receipts(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert _AckSyncHandler.requests[1]["syncContext"]["policyBundleAcknowledgement"] == {
        "appliedAt": "2026-06-05T13:30:01+00:00",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": "policy-2026-06-05.4",
        "deviceId": guard_runner_module._guard_device_metadata(store)[0],
        "deviceName": guard_runner_module._guard_device_metadata(store)[1],
        "status": "synced",
    }


def test_sync_receipts_rejects_policy_bundle_for_the_wrong_workspace(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-a")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-a"),
        "2026-06-05T13:29:00Z",
    )
    bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-06-05.5",
        "bundleHash": "",
        "issuedAt": "2026-06-05T13:30:00+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
        "workspaceId": "workspace-b",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [],
        "acknowledgements": [],
    }
    bundle = sign_policy_bundle(bundle, workspace_id="workspace-b")

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
                "syncedAt": "2026-06-05T13:30:01+00:00",
                "receiptsStored": 0,
                "policyBundle": bundle,
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_last_good") is None
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(last_error, dict)
    assert last_error["reason"] == "wrong_workspace"
    assert "Reconnect Guard" in str(last_error["message"])
