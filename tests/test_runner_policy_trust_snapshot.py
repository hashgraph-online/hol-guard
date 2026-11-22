"""A Guard Cloud sync selects with one trust-row snapshot and activates with a fresh one."""

from __future__ import annotations

import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_bundle_trusted_keys import PolicyBundleVerificationKey
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy_trust_rows import PolicyBundleTrustRows
from tests.policy_bundle_signing_helpers import policy_bundle_test_verification_key
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_review_key_sync import _WORKSPACE_ID, _connected_store, _policy_bundle, _Response

_SNAPSHOT_KEYRING: dict[str, object] = {"snapshot": "keyring"}
_SNAPSHOT_SUPPLY_CHAIN: dict[str, object] = {"snapshot": "supply-chain"}
_SNAPSHOT_PROVENANCE: dict[str, object] = {"snapshot": "provenance"}
_SNAPSHOT_WORKSPACE = "workspace-from-snapshot"
_ACTIVATION_SUPPLY_CHAIN: dict[str, object] = {"activation": "supply-chain"}
_ACTIVATION_PROVENANCE: dict[str, object] = {"activation": "provenance"}
_ACTIVATION_WORKSPACE = "workspace-from-activation-snapshot"


def test_the_synced_bundle_is_validated_with_the_snapshot_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    policy_key = policy_bundle_test_verification_key(workspace_id=_WORKSPACE_ID)
    read_trust_rows = store.policy_bundle_trust_rows
    snapshots: list[PolicyBundleTrustRows] = []
    activation_snapshots: list[PolicyBundleTrustRows] = []

    def snapshot(**kwargs: bool) -> PolicyBundleTrustRows:
        rows = read_trust_rows(**kwargs)
        if kwargs.get("keys_only"):
            # The final trust check reads the rows again; a rotation that
            # landed after selection must be what activation is judged by.
            rows = replace(
                rows,
                supply_chain_keyring=_ACTIVATION_SUPPLY_CHAIN,
                managed_keyring_provenance=_ACTIVATION_PROVENANCE,
                workspace_id=_ACTIVATION_WORKSPACE,
            )
            activation_snapshots.append(rows)
            return rows
        rows = replace(
            rows,
            policy_bundle_keyring=_SNAPSHOT_KEYRING,
            supply_chain_keyring=_SNAPSHOT_SUPPLY_CHAIN,
            managed_keyring_provenance=_SNAPSHOT_PROVENANCE,
            workspace_id=_SNAPSHOT_WORKSPACE,
        )
        snapshots.append(rows)
        return rows

    validations: list[dict[str, object]] = []

    def validate_policy_bundle(
        policy_bundle: dict[str, object],
        **kwargs: object,
    ) -> tuple[dict[str, object], None, tuple[PolicyBundleVerificationKey, ...]]:
        validations.append(kwargs)
        return policy_bundle, None, (policy_key,)

    def open_sync(_request: urllib.request.Request, timeout: float) -> _Response:
        del _request, timeout
        return _Response(
            {
                "syncedAt": "2026-08-26T12:00:00+00:00",
                "receiptsStored": 0,
                "policyBundle": _policy_bundle(),
            }
        )

    def no_auxiliary_sync(_store: GuardStore, auth_context: dict[str, object] | None = None) -> int:
        del _store, auth_context
        return 0

    monkeypatch.setattr(store, "policy_bundle_trust_rows", snapshot)
    monkeypatch.setattr(runner, "validate_synced_policy_bundle", validate_policy_bundle)
    stub_authenticated_urlopen(monkeypatch, open_sync)
    monkeypatch.setattr(runner, "sync_pain_signals", no_auxiliary_sync)
    monkeypatch.setattr(runner, "sync_guard_events", no_auxiliary_sync)

    _ = runner.sync_receipts(
        store,
        auth_context={
            "access_token": "test-access-token",
            "dpop_key_material": None,
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
    )

    assert snapshots
    candidate = validations[0]
    assert candidate["stored_keyring"] is _SNAPSHOT_KEYRING
    assert candidate["supply_chain_keyring"] is _SNAPSHOT_SUPPLY_CHAIN
    assert candidate["managed_keyring_provenance"] is _SNAPSHOT_PROVENANCE
    assert candidate["expected_workspace_id"] == _SNAPSHOT_WORKSPACE
    assert len(activation_snapshots) == 1
    assert len(validations) >= 2
    activation = validations[-1]
    assert activation["supply_chain_keyring"] is _ACTIVATION_SUPPLY_CHAIN
    assert activation["managed_keyring_provenance"] is _ACTIVATION_PROVENANCE
    assert activation["expected_workspace_id"] == _ACTIVATION_WORKSPACE


def test_a_rejected_sync_judges_the_last_good_bundle_with_its_own_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    last_good = {"bundleVersion": "last-good"}
    store.set_sync_payload("policy_bundle_last_good", last_good, "2026-08-26T11:00:00+00:00")
    read_trust_rows = store.policy_bundle_trust_rows
    last_good_snapshots: list[PolicyBundleTrustRows] = []

    def snapshot(**kwargs: bool) -> PolicyBundleTrustRows:
        rows = read_trust_rows(**kwargs)
        if kwargs.get("last_good"):
            rows = replace(rows, policy_bundle_keyring=_SNAPSHOT_KEYRING, workspace_id=_SNAPSHOT_WORKSPACE)
            last_good_snapshots.append(rows)
        return rows

    judged: list[tuple[object, PolicyBundleTrustRows | None]] = []

    def validate_cached(
        _store: GuardStore,
        policy_bundle: object,
        *,
        rows: PolicyBundleTrustRows | None = None,
    ) -> tuple[None, str]:
        judged.append((policy_bundle, rows))
        return None, "invalid_policy_bundle"

    def reject_policy_bundle(
        _policy_bundle: dict[str, object],
        **_kwargs: object,
    ) -> tuple[None, str, tuple[PolicyBundleVerificationKey, ...]]:
        return None, "policy_bundle_signature_invalid", ()

    def open_sync(_request: urllib.request.Request, timeout: float) -> _Response:
        del _request, timeout
        return _Response(
            {
                "syncedAt": "2026-08-26T12:00:00+00:00",
                "receiptsStored": 0,
                "policyBundle": _policy_bundle(),
            }
        )

    def no_auxiliary_sync(_store: GuardStore, auth_context: dict[str, object] | None = None) -> int:
        del _store, auth_context
        return 0

    monkeypatch.setattr(store, "policy_bundle_trust_rows", snapshot)
    monkeypatch.setattr(runner, "validate_synced_policy_bundle", reject_policy_bundle)
    monkeypatch.setattr(runner, "_validate_cached_policy_bundle", validate_cached)
    stub_authenticated_urlopen(monkeypatch, open_sync)
    monkeypatch.setattr(runner, "sync_pain_signals", no_auxiliary_sync)
    monkeypatch.setattr(runner, "sync_guard_events", no_auxiliary_sync)

    _ = runner.sync_receipts(
        store,
        auth_context={
            "access_token": "test-access-token",
            "dpop_key_material": None,
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
    )

    assert len(last_good_snapshots) == 1
    rows = last_good_snapshots[0]
    assert (last_good, rows) in judged
    assert rows.policy_bundle_keyring is _SNAPSHOT_KEYRING
