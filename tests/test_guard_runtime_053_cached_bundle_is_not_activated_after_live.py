"""Runtime regression tests: cached bundle is not activated after live."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    Path,
    PolicyDecision,
    guard_runner_module,
    json,
    policy_bundle_test_keyring,
    pytest,
    stub_authenticated_urlopen,
    synced_policy_module,
    synced_policy_payload,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_runtime_test_support import (
    _seed_guard_cloud,
    _signed_test_package_block_bundle,
    _signed_test_policy_bundle,
)


def test_cached_bundle_is_not_activated_after_live_anchor_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-07-17T00:00:00Z",
    )
    cached_bundle = _signed_test_package_block_bundle(
        bundle_version="policy-2026-07-17.anchor-race",
        issued_at="2026-07-17T00:00:00Z",
    )
    store.set_sync_payload("policy_bundle", cached_bundle, "2026-07-17T00:00:00Z")

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
                "syncedAt": "2026-07-17T00:00:01Z",
                "receiptsStored": 0,
            }
        )

    real_validate = guard_runner_module.validate_synced_policy_bundle
    cached_validation_calls = 0
    final_validation_calls = 0

    def _initial_anchor(*args, **kwargs):
        nonlocal cached_validation_calls
        cached_validation_calls += 1
        return real_validate(*args, **kwargs)

    def _revoked_anchor(*args, **kwargs):
        nonlocal final_validation_calls
        final_validation_calls += 1
        return None, "signing_key_revoked", ()

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "validate_synced_policy_bundle", _revoked_anchor)
    monkeypatch.setattr(synced_policy_module, "validate_synced_policy_bundle", _initial_anchor)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    summary = guard_runner_module.sync_receipts(store)

    assert cached_validation_calls >= 1
    assert final_validation_calls == 1
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_last_error")["reason"] == "signing_key_revoked"
    assert store.list_policy_decisions() == []
    assert summary["remote_policies_stored"] == 0


def test_omitted_bundle_with_invalid_cached_authority_clears_unsigned_legacy_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-07-17T00:00:00Z",
    )
    expired_current = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2020-01-01.1",
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    invalid_last_good = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2026-07-16.1",
        issued_at="2026-07-16T00:00:00Z",
    )
    invalid_last_good["bundleHash"] = "sha256:tampered-last-good"
    store.set_sync_payload("policy_bundle", expired_current, "2020-01-01T00:00:00Z")
    store.set_sync_payload("policy_bundle_last_good", invalid_last_good, "2026-07-16T00:00:00Z")
    store.set_sync_payload(
        "policy",
        {"mode": "observe", "defaultAction": "allow"},
        "2026-07-16T00:00:00Z",
    )
    store.set_sync_payload(
        "team_policy_pack",
        {"name": "Stale unsigned policy", "allowedPublishers": ["stale.publisher.example"]},
        "2026-07-16T00:00:00Z",
    )
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="*",
                scope="artifact",
                action="allow",
                artifact_id="stale-cloud-allow",
                source="cloud-sync",
            ),
            PolicyDecision(
                harness="*",
                scope="publisher",
                action="allow",
                publisher="stale.publisher.example",
                source="team-policy",
            ),
            PolicyDecision(
                harness="*",
                scope="artifact",
                action="allow",
                artifact_id="stale-bundle-allow",
                source="policy-bundle",
            ),
        ],
        "2026-07-16T00:00:00Z",
        remote_write_authorized=True,
    )
    store.set_cloud_exceptions(
        [
            {
                "id": "stored-unsigned-exception",
                "effect": "allow",
                "scope": "artifact",
                "harness": "*",
                "owner": "attacker@example.com",
                "expiry": "2099-01-01T00:00:00+00:00",
                "provenance": "receipt-sync",
            }
        ],
        "2026-07-16T00:00:00Z",
    )
    response_payload = {
        "syncedAt": "2026-07-17T00:00:01Z",
        "receiptsStored": 0,
        "policy": {"mode": "observe", "defaultAction": "allow"},
        "teamPolicyPack": {
            "name": "New unsigned policy",
            "allowedPublishers": ["new.publisher.example"],
        },
        "exceptions": [
            {
                "exceptionId": "new-unsigned-exception",
                "scope": "artifact",
                "harness": "*",
                "artifactId": "new-unsigned-allow",
                "owner": "attacker@example.com",
                "expiresAt": "2099-01-01T00:00:00Z",
            }
        ],
    }

    assert {item["source"] for item in store.list_policy_decisions()} == {
        "cloud-sync",
        "team-policy",
        "policy-bundle",
    }
    raw_cloud_exceptions = store.get_sync_payload("cloud_exceptions")
    assert isinstance(raw_cloud_exceptions, list)
    assert [item["id"] for item in raw_cloud_exceptions if isinstance(item, dict)] == ["stored-unsigned-exception"]
    # Cached exception rows are never authority without a currently valid,
    # signed policy bundle, even before the next sync clears the stale cache.
    assert store.list_cloud_exceptions() == []

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
        return _Response(response_payload)

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    summary = guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy") == {}
    assert store.get_sync_payload("team_policy_pack") == {}
    assert store.list_policy_decisions() == []
    assert store.list_cloud_exceptions() == []
    assert synced_policy_payload(store) is None
    assert store.resolve_policy("codex", "stale-cloud-allow", "hash") is None
    assert store.resolve_policy("codex", "stale-bundle-allow", "hash") is None
    assert store.resolve_policy("codex", "new-unsigned-allow", "hash") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="stale.publisher.example") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="new.publisher.example") is None
    assert summary["exceptions_stored"] == 0
    assert summary["cloud_exceptions_stored"] == 0
    assert summary["remote_policies_stored"] == 0


@pytest.mark.parametrize(
    ("malformed_bundle", "cached_authority"),
    [
        (None, "current"),
        ("not-a-policy-bundle", "last-good"),
        ([], None),
    ],
    ids=("null-preserves-current", "string-preserves-last-good", "list-without-fallback"),
)
def test_malformed_policy_bundle_field_rejects_unsigned_siblings_and_preserves_signed_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed_bundle: object,
    cached_authority: str | None,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-07-17T00:00:00Z",
    )
    cached_bundle = _signed_test_package_block_bundle(
        bundle_version="policy-2026-07-17.2",
        issued_at="2026-07-17T00:00:00Z",
    )
    if cached_authority == "current":
        store.set_sync_payload("policy_bundle", cached_bundle, "2026-07-17T00:00:00Z")
    elif cached_authority == "last-good":
        store.set_sync_payload("policy_bundle_last_good", cached_bundle, "2026-07-17T00:00:00Z")

    response_payload: dict[str, object] = {
        "syncedAt": "2026-07-17T00:00:01Z",
        "receiptsStored": 0,
        "policyBundle": malformed_bundle,
        "policy": {"mode": "observe", "defaultAction": "allow"},
        "teamPolicyPack": {
            "name": "Malformed bundle unsigned sibling",
            "allowedPublishers": ["malformed.publisher.example"],
        },
        "exceptions": [
            {
                "exceptionId": "malformed-unsigned-exception",
                "scope": "artifact",
                "harness": "*",
                "artifactId": "malformed-unsigned-allow",
                "owner": "attacker@example.com",
                "expiresAt": "2099-01-01T00:00:00Z",
            }
        ],
    }

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
        return _Response(response_payload)

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    summary = guard_runner_module.sync_receipts(store)

    expected_current = cached_bundle if cached_authority is not None else None
    expected_signed_rows = (
        [("codex", "harness", "family:package-request", "block", "signed-package-block")]
        if cached_authority is not None
        else []
    )
    assert store.get_sync_payload("policy_bundle") == expected_current
    if cached_authority == "last-good":
        assert store.get_sync_payload("policy_bundle_last_good") == cached_bundle
    assert store.get_sync_payload("policy_bundle_last_error")["reason"] == "invalid_policy_bundle"
    assert store.get_sync_payload("policy") == {}
    assert store.get_sync_payload("team_policy_pack") == {}
    assert [
        (item["harness"], item["scope"], item["artifact_id"], item["action"], item["owner"])
        for item in store.list_policy_decisions()
    ] == expected_signed_rows
    assert store.list_cloud_exceptions() == []
    assert store.resolve_policy("codex", "malformed-unsigned-allow", "hash") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="malformed.publisher.example") is None
    assert summary["exceptions_stored"] == 0
    assert summary["cloud_exceptions_stored"] == 0
    assert summary["remote_policies_stored"] == len(expected_signed_rows)
    if cached_authority is not None:
        assert store.resolve_policy("codex", "codex:project:package-request:cached", "hash") == "block"
