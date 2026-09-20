"""Runtime regression tests: sync receipts preserves last known good policy."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardConfig,
    GuardStore,
    Path,
    guard_runner_module,
    json,
    overlay_synced_guard_policy,
    payload_hash_for_policy_bundle,
    policy_bundle_test_keyring,
    pytest,
    sign_policy_bundle,
    stub_authenticated_urlopen,
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


def test_sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-04-19T00:00:00Z")

    valid_bundle = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.2",
        "bundleHash": "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
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
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
                "artifactType": "package_request",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": [],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }
    valid_bundle = sign_policy_bundle(valid_bundle)
    invalid_bundle = dict(valid_bundle)
    invalid_bundle["bundleVersion"] = "policy-2026-04-19.3"
    invalid_bundle["issuedAt"] = "2026-04-19T00:00:11+00:00"
    invalid_bundle["rules"] = [{**valid_bundle["rules"][0], "action": "allow"}]
    invalid_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    invalid_bundle["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(invalid_bundle)
    invalid_bundle["payloadHash"] = payload_hash_for_policy_bundle(invalid_bundle)
    invalid_bundle["verifier"]["signature"] = invalid_bundle["payloadHash"]
    inactive_bundle = dict(valid_bundle)
    inactive_bundle["bundleVersion"] = "policy-2026-04-19.4"
    inactive_bundle["issuedAt"] = "2026-04-19T00:00:13+00:00"
    inactive_bundle["rolloutState"] = "simulated"
    inactive_bundle = sign_policy_bundle(inactive_bundle)

    responses = iter(
        [
            {
                "syncedAt": "2026-04-19T00:00:11+00:00",
                "receiptsStored": 0,
                "policyBundle": valid_bundle,
            },
            {
                "syncedAt": "2026-04-19T00:00:12+00:00",
                "receiptsStored": 0,
                "policyBundle": invalid_bundle,
            },
            {
                "syncedAt": "2026-04-19T00:00:13+00:00",
                "receiptsStored": 0,
                "policyBundle": inactive_bundle,
            },
        ]
    )

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
        return _Response(next(responses))

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    guard_runner_module.sync_receipts(store)
    first_bundle = store.get_sync_payload("policy_bundle")
    guard_runner_module.sync_receipts(store)

    assert first_bundle == store.get_sync_payload("policy_bundle")
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert last_error["reason"] == "unsupported_signature_algorithm"
    assert "Sync again" in last_error["message"]
    assert store.resolve_policy("codex", "codex:project:package-request:persisted", "hash") == "block"

    guard_runner_module.sync_receipts(store)

    assert first_bundle == store.get_sync_payload("policy_bundle")
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert last_error["reason"] == "inactive_rollout_state"
    assert "not active for local enforcement" in last_error["message"]
    assert store.resolve_policy("codex", "codex:project:package-request:persisted", "hash") == "block"


def test_invalid_bundle_cannot_fall_back_to_co_delivered_unsigned_policy(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id="workspace-1"),
        "2026-04-19T00:00:00Z",
    )
    invalid_bundle = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2026-04-19.3",
        issued_at="2026-04-19T00:00:00Z",
    )
    invalid_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    invalid_bundle["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(invalid_bundle)
    invalid_bundle["payloadHash"] = payload_hash_for_policy_bundle(invalid_bundle)
    invalid_bundle["verifier"]["signature"] = invalid_bundle["payloadHash"]

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "syncedAt": "2026-04-19T00:00:01Z",
                    "receiptsStored": 0,
                    "policyBundle": invalid_bundle,
                    "policy": {"mode": "observe", "defaultAction": "allow"},
                    "teamPolicyPack": {
                        "name": "Unsigned fallback",
                        "allowedPublishers": ["attacker.example"],
                    },
                    "exceptions": [
                        {
                            "scope": "artifact",
                            "harness": "*",
                            "artifactId": "attacker-allow",
                            "reason": "Unsigned fallback allow",
                            "expiresAt": "2099-01-01T00:00:00Z",
                        }
                    ],
                }
            ).encode("utf-8")

    def _fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return type(
                "_EventsResponse",
                (),
                {
                    "__enter__": lambda self: self,
                    "__exit__": lambda self, exc_type, exc, tb: False,
                    "read": lambda self: b'{"accepted":0,"statuses":[]}',
                },
            )()
        return _Response()

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    summary = guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy") == {}
    assert store.get_sync_payload("team_policy_pack") == {}
    assert store.resolve_policy("codex", "attacker-allow", "hash") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="attacker.example") is None
    assert store.list_cloud_exceptions() == []
    assert summary["exceptions_stored"] == 0
    assert store.get_sync_payload("policy_bundle_last_error")["reason"] == "unsupported_signature_algorithm"


def test_valid_signed_empty_bundle_excludes_co_delivered_unsigned_policy_siblings(
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
    signed_bundle = _signed_test_policy_bundle(
        [],
        bundle_version="policy-2026-07-17.1",
        issued_at="2026-07-17T00:00:00Z",
    )
    response_payload = {
        "syncedAt": "2026-07-17T00:00:01Z",
        "receiptsStored": 0,
        "policyBundle": signed_bundle,
        "policy": {
            "mode": "observe",
            "defaultAction": "allow",
            "newNetworkDomainAction": "allow",
            "subprocessAction": "allow",
        },
        "teamPolicyPack": {
            "name": "Unsigned sibling policy",
            "allowedPublishers": ["unsigned.publisher.example"],
            "blockedArtifacts": ["unsigned-team-block"],
        },
        "exceptions": [
            {
                "exceptionId": "unsigned-exception",
                "scope": "artifact",
                "harness": "*",
                "artifactId": "unsigned-exception-artifact",
                "owner": "attacker@example.com",
                "reason": "Unsigned sibling allow",
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
    effective_config = overlay_synced_guard_policy(
        GuardConfig(
            guard_home=store.guard_home,
            workspace=None,
            mode="enforce",
            default_action="block",
            new_network_domain_action="block",
            subprocess_action="block",
        ),
        synced_policy_payload(store),
    )

    assert store.get_sync_payload("policy_bundle") == signed_bundle
    assert store.get_sync_payload("policy") == {}
    assert store.get_sync_payload("team_policy_pack") == {}
    assert store.list_policy_decisions() == []
    assert store.list_cloud_exceptions() == []
    assert store.resolve_policy("codex", "unsigned-exception-artifact", "hash") is None
    assert store.resolve_policy("codex", "unsigned-team-block", "hash") is None
    assert store.resolve_policy("codex", "other", "hash", publisher="unsigned.publisher.example") is None
    assert summary["exceptions_stored"] == 0
    assert summary["cloud_exceptions_stored"] == 0
    assert summary["remote_policies_stored"] == 0
    assert effective_config.mode == "enforce"
    assert effective_config.default_action == "block"
    assert effective_config.new_network_domain_action == "block"
    assert effective_config.subprocess_action == "block"


def test_fresh_mdm_activation_bootstraps_first_signed_policy_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.mdm import lifecycle as mdm_lifecycle
    from codex_plugin_scanner.guard.mdm import policy as mdm_policy
    from codex_plugin_scanner.guard.mdm.contracts import (
        MDM_POLICY_SCHEMA_VERSION,
        ManagedPolicyState,
    )

    home = tmp_path / "home"
    home.mkdir()
    keyring = policy_bundle_test_keyring(workspace_id="workspace-1")
    managed_policy = mdm_policy.parse_managed_policy(
        {
            "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
            "settings": {},
            "policyBundleKeyring": keyring,
        }
    )
    managed_state = ManagedPolicyState(
        "active",
        "managed-policy-test",
        policy=managed_policy,
    )
    monkeypatch.setattr(mdm_lifecycle, "load_managed_policy", lambda: managed_state)
    monkeypatch.setattr(mdm_policy, "load_managed_policy", lambda: managed_state)
    monkeypatch.setattr(
        mdm_lifecycle,
        "apply_managed_install",
        lambda *_args, **_kwargs: {"managed_installs": []},
    )

    mdm_lifecycle.activate_user(home, "developer")
    store = GuardStore(home / ".hol-guard")
    local_keyring = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(local_keyring, dict)
    assert local_keyring["keys"] == []
    assert store.get_sync_payload("managed_policy_bundle_keyring_mirror") == keyring
    _seed_guard_cloud(store, workspace_id="workspace-1")
    signed_bundle = _signed_test_package_block_bundle(
        bundle_version="policy-2026-07-17.mdm-bootstrap",
        issued_at="2026-07-17T00:00:00Z",
    )

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
                "policyBundle": signed_bundle,
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)

    summary = guard_runner_module.sync_receipts(store)

    assert store.get_sync_payload("policy_bundle") == signed_bundle
    persisted_local_keyring = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(persisted_local_keyring, dict)
    assert persisted_local_keyring["keys"] == []
    assert store.get_sync_payload("managed_policy_bundle_keyring_mirror") == keyring
    assert summary["remote_policies_stored"] == 1
    assert (
        store.resolve_policy(
            "codex",
            "codex:project:package-request:fresh-managed-device",
            "hash",
        )
        == "block"
    )
