"""Complete signed expressions stage separately from generic policy rows."""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_NOW = "2026-09-17T00:00:00Z"
_LATER = "2026-09-17T00:01:00Z"
_TIME = datetime(2026, 9, 17, tzinfo=timezone.utc).timestamp()
_WORKSPACE = "00000000-0000-4000-8000-000000000061"


def _path_child(parent: dict[str, Any] | list[Any], part: str) -> dict[str, Any] | list[Any]:
    child = parent[int(part)] if isinstance(parent, list) else parent[part]
    assert isinstance(child, (dict, list))
    return child


def _fixture(
    tmp_path: Path,
    *,
    generic: bool = True,
    generic_target: bool = False,
    second_generic: bool = False,
    changes: dict[str, Any] | None = None,
):
    store = GuardStore(tmp_path / "guard-home")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id=_WORKSPACE)
    plain: dict[str, Any] = {
        "id": "generic.rule",
        "enabled": True,
        "effect": "allow",
        "match": {"harnesses": ["codex"], "artifacts": ["synthetic-generic"]},
        "lifetime": {"mode": "permanent", "expiresAt": None},
        "provenance": {"source": "cloud", "createdAt": _NOW},
    }
    if generic_target:
        plain["match"]["devices"] = [store.get_device_metadata()["installation_id"]]
    command = copy.deepcopy(plain)
    command.update({"id": "command.rule", "effect": "block"})
    command["match"] = {
        "harnesses": ["codex"],
        "artifacts": ["synthetic-command"],
        "commands": {
            "combinator": "all",
            "conditions": [
                {
                    "field": "command",
                    "operator": "startsWith",
                    "value": "printf",
                    "caseSensitive": True,
                }
            ],
        },
    }
    if changes:
        for path, value in changes.items():
            parent: dict[str, Any] | list[Any] = command
            parts = path.split(".")
            for part in parts[:-1]:
                parent = _path_child(parent, part)
            assert isinstance(parent, dict)
            parent[parts[-1]] = value
    generic_rules = [plain] if generic else []
    if second_generic:
        sibling = copy.deepcopy(plain)
        sibling["id"] = "generic.second"
        sibling["match"]["artifacts"] = ["synthetic-generic-two"]
        generic_rules.append(sibling)
    payload: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.commands", "name": "Synthetic commands", "revision": 7},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "warn"},
            "rules": [*generic_rules, command],
        },
    }
    bundle = _signed_bundle(private, key, payload_base=payload, rollout_state="enforcing", bundle_version=9)
    bundle["workspaceId"] = _WORKSPACE
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(
        private.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": _WORKSPACE}, _NOW)
    keyring = policy_bundle_keyring_payload((key,), workspace_id=_WORKSPACE)
    validated, reason, _ = validate_synced_policy_bundle(bundle, stored_keyring=keyring, now=_TIME)
    assert reason is None and validated == bundle
    return store, bundle, keyring


def _generic() -> PolicyDecision:
    return PolicyDecision(
        harness="codex",
        scope="artifact",
        action="allow",
        artifact_id="synthetic-generic",
        owner="generic.rule",
        source="policy-bundle-canonical",
    )


def _apply(store, bundle, keyring, decisions, now=_NOW):
    return store.apply_policy_bundle_authority(
        decisions,
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=keyring,
        cloud_exceptions=[],
        policy_bundle_ack={
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": 9,
            "status": "received",
        },
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )


def test_expression_only_stages_full_source_with_zero_generic_rows_and_authenticated_recency(tmp_path: Path) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic=False)
    assert _apply(store, bundle, keyring, []) is not None
    record = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(record, dict)
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("policy_bundle") == bundle
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "received"
    reopened = GuardStore(store.guard_home)
    assert _apply(reopened, bundle, keyring, [], _LATER) is not None
    assert reopened.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == record
    assert reopened.list_policy_decisions() == []


def test_mixed_source_generic_row_remains_authenticated_without_expression_selector_cache(tmp_path: Path) -> None:
    store, bundle, keyring = _fixture(tmp_path)
    assert _apply(store, bundle, keyring, [_generic()]) is not None
    lookup = store.resolve_policy_decision_lookup("codex", "synthetic-generic", now=_NOW, consume_one_shot=False)
    assert isinstance(lookup["decision"], dict)
    assert lookup["decision"]["owner"] == "generic.rule"
    assert [row["artifact_id"] for row in store.list_policy_decisions()] == ["synthetic-generic"]


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [
            _generic(),
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="block",
                artifact_id="synthetic-command",
                owner="command.rule",
                source="policy-bundle-canonical",
            ),
        ],
    ],
)
def test_store_refuses_omitted_generic_or_expression_selector_rows_before_writing(tmp_path: Path, rows) -> None:
    store, bundle, keyring = _fixture(tmp_path)
    assert _apply(store, bundle, keyring, rows) is None
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
    assert store.list_policy_decisions() == []


@pytest.mark.parametrize(
    "changes",
    [
        {"match.devices": ["other-installation"], "match.commands.conditions.0.operator": "regex"},
        {
            "lifetime.mode": "until",
            "lifetime.expiresAt": "2026-09-16T00:00:00Z",
            "match.commands.conditions.0.operator": "glob",
        },
        {"match.commands.conditions.0.caseSensitive": False},
    ],
)
def test_store_refuses_unsupported_active_expression_even_off_target_or_expired(tmp_path: Path, changes) -> None:
    store, bundle, keyring = _fixture(tmp_path, changes=changes)
    assert _apply(store, bundle, keyring, [_generic()]) is None
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.list_policy_decisions() == []


def test_adapter_returns_only_generic_decisions_and_preserves_complete_source(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.policy_bundle_staging import prepare_canonical_policy_bundle_staging

    store, bundle, _ = _fixture(tmp_path)
    original = copy.deepcopy(bundle)
    device = store.get_device_metadata()
    staged = prepare_canonical_policy_bundle_staging(
        bundle,
        device_id=device["installation_id"],
        device_name=device["device_label"],
    )
    assert staged.decisions == (_generic(),)
    assert staged.require_source_binding is True
    assert bundle == original


@pytest.mark.parametrize(
    "changes",
    [
        {"match.devices": ["other-installation"]},
        {"lifetime.mode": "until", "lifetime.expiresAt": "2026-09-16T00:00:00Z"},
    ],
)
def test_supported_off_target_or_expired_source_still_gets_authenticated_binding(tmp_path: Path, changes) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic=False, changes=changes)
    assert _apply(store, bundle, keyring, []) is not None
    assert isinstance(store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY), dict)
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("policy_bundle") == bundle


@pytest.mark.parametrize(
    "field,value",
    [
        ("mac", "0" * 64),
        ("materializedAt", "2026-09-17T00:02:00.000000+00:00"),
        ("deviceId", "different-installation"),
    ],
)
def test_zero_row_retry_refuses_tampered_binding_without_repairing_it(tmp_path: Path, field, value) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic=False)
    assert _apply(store, bundle, keyring, []) is not None
    binding = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(binding, dict)
    binding[field] = value
    store.set_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY, binding, _LATER)
    before = store.get_sync_payload("policy_bundle_ack")
    assert _apply(store, bundle, keyring, [], _LATER) is None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == binding
    assert store.get_sync_payload("policy_bundle_ack") == before
    assert store.list_policy_decisions() == []


def test_binding_source_rows_and_ack_roll_back_together_on_real_sql_failure(tmp_path: Path) -> None:
    import sqlite3

    store, bundle, keyring = _fixture(tmp_path)
    with store._connect() as connection:
        connection.execute(
            "create trigger fail_staged_ack before insert on sync_state "
            "when new.state_key='policy_bundle_ack' begin select raise(abort, 'fixture_abort'); end"
        )
    with pytest.raises(sqlite3.IntegrityError, match="fixture_abort"):
        _apply(store, bundle, keyring, [_generic()])
    assert store.list_policy_decisions() == []
    for name in (
        "policy_bundle",
        "policy_bundle_last_good",
        "policy_bundle_ack",
        "policy_bundle_acceptance_checkpoint",
        POLICY_BUNDLE_MATERIALIZATION_KEY,
    ):
        assert store.get_sync_payload(name) is None


def test_staged_source_does_not_claim_applied_or_suppress_existing_invalidation(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import store_policy

    store, bundle, keyring = _fixture(tmp_path, generic=False)
    calls = []
    monkeypatch.setattr(
        store_policy, "notify_native_policy_mutation", lambda home, **kwargs: calls.append((home, kwargs))
    )
    assert _apply(store, bundle, keyring, []) is not None
    assert _apply(store, bundle, keyring, [], _LATER) is not None
    assert calls == [(store.guard_home, {"require_source_authority": True})] * 2
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "received"
    assert store.get_sync_payload("policy_bundle_applied") is None


def test_store_revalidates_generic_target_against_transaction_device(tmp_path: Path, monkeypatch) -> None:
    store, bundle, keyring = _fixture(tmp_path, generic_target=True)
    original = store._prepared_remote_policy_rows

    def change_device_after_rows(*args, **kwargs):
        prepared = original(*args, **kwargs)
        with store._connect() as connection:
            connection.execute(
                "update guard_devices set installation_id='different-installation' where device_key='local-device'"
            )
        return prepared

    monkeypatch.setattr(store, "_prepared_remote_policy_rows", change_device_after_rows)
    assert _apply(store, bundle, keyring, [_generic()]) is None
    assert store.get_sync_payload("policy_bundle") is None
    assert store.list_policy_decisions() == []


@pytest.mark.parametrize(
    "shape,accepted",
    [
        ("reversed", True),
        ("omitted", False),
        ("substituted_duplicate", False),
        ("extra_duplicate", False),
    ],
)
def test_generic_staging_compares_complete_multiset_without_requiring_row_order(
    tmp_path: Path, shape, accepted
) -> None:
    from dataclasses import replace

    store, bundle, keyring = _fixture(tmp_path, second_generic=True)
    first = _generic()
    second = replace(first, owner="generic.second", artifact_id="synthetic-generic-two")
    rows = {
        "reversed": [second, first],
        "omitted": [first],
        "substituted_duplicate": [first, first],
        "extra_duplicate": [second, first, first],
    }[shape]
    assert (_apply(store, bundle, keyring, rows) is not None) is accepted
    if accepted:
        assert {row["owner"] for row in store.list_policy_decisions()} == {"generic.rule", "generic.second"}
    else:
        assert store.list_policy_decisions() == []
        assert store.get_sync_payload("policy_bundle") is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("harness", "cursor"),
        ("scope", "workspace"),
        ("action", "block"),
        ("artifact_id", "synthetic-other"),
        ("artifact_hash", "b" * 64),
        ("workspace", "synthetic-workspace"),
        ("publisher", "synthetic-publisher"),
        ("reason", "synthetic-reason"),
        ("owner", "generic.other"),
        ("source", "local"),
        ("expires_at", _LATER),
        ("exact_command_sha256", "a" * 64),
    ],
)
def test_generic_staging_field_mismatch_preserves_existing_transaction_state(
    tmp_path: Path, field: str, value: object
) -> None:
    from dataclasses import replace

    store, bundle, keyring = _fixture(tmp_path, second_generic=True)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="synthetic-local"), _NOW
    )
    before_rows = store.list_policy_decisions()
    preserved_keys = (
        "policy_bundle",
        "policy_bundle_ack",
        "policy_bundle_checkpoint",
        POLICY_BUNDLE_MATERIALIZATION_KEY,
        "oauth_local_credentials",
    )
    before_payloads = {key: store.get_sync_payload(key) for key in preserved_keys}
    first = _generic()
    second = replace(first, owner="generic.second", artifact_id="synthetic-generic-two")
    assert _apply(store, bundle, keyring, [replace(first, **{field: value}), second]) is None
    assert store.list_policy_decisions() == before_rows
    assert {key: store.get_sync_payload(key) for key in preserved_keys} == before_payloads


@pytest.mark.parametrize(
    "shape,accepted",
    [
        ("matching", True),
        ("permuted", True),
        ("duplicate_first", False),
        ("duplicate_second", False),
        ("additional_duplicate", False),
    ],
)
def test_generic_staging_multiplicity_retains_local_authority_on_acceptance_and_refusal(
    tmp_path: Path, shape: str, accepted: bool
) -> None:
    from dataclasses import replace

    store, bundle, keyring = _fixture(tmp_path, second_generic=True)
    local = PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="synthetic-local")
    store.upsert_policy(local, _NOW)
    before_rows = store.list_policy_decisions()
    first = _generic()
    second = replace(first, owner="generic.second", artifact_id="synthetic-generic-two")
    decisions = {
        "matching": [first, second],
        "permuted": [second, first],
        "duplicate_first": [first, first],
        "duplicate_second": [second, second],
        "additional_duplicate": [second, first, first],
    }[shape]
    assert (_apply(store, bundle, keyring, decisions) is not None) is accepted
    rows = store.list_policy_decisions()
    assert [row for row in rows if row["source"] == "local"] == before_rows
    if accepted:
        assert {row["owner"] for row in rows if row["source"] == "policy-bundle-canonical"} == {
            "generic.rule",
            "generic.second",
        }
        assert store.get_sync_payload("policy_bundle") == bundle
        acknowledgement = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(acknowledgement, dict) and acknowledgement["status"] == "received"
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is not None
    else:
        assert rows == before_rows
        assert store.get_sync_payload("policy_bundle") is None
        assert store.get_sync_payload("policy_bundle_ack") is None
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
