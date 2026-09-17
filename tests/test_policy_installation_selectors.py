"""Installation selectors through signed sync and actual local policy lookup."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_ack_contract import generic_ack_matches_bundle
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import PolicyBundleVerificationKey
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _sync_signed_v2_bundle,
)

NOW = "2026-09-17T12:00:00Z"
ARTIFACT = "skill:installation-target"


@pytest.fixture
def key_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, _verification_key(private, workspace_id="workspace-alpha")


def store_at(path: Path, key: PolicyBundleVerificationKey, label: str) -> GuardStore:
    store = _seed_v2_admission_store(path, key)
    store.set_device_label(label, NOW)
    return store


def bundle_for(key_pair, selectors: list[str]):
    payload = _generic_v2_payload(rule_id="machine-only", artifact_id=ARTIFACT)
    rule = payload["spec"]["rules"][0]
    rule["match"]["devices"] = selectors
    rule["match"]["harnesses"] = ["codex", "cursor"]
    return _signed_bundle(*key_pair, payload_base=payload)


def sync(store: GuardStore, bundle, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at=NOW)
    assert store.get_sync_payload("policy_bundle") == bundle
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    assert generic_ack_matches_bundle(acknowledgement, bundle, device_id=store.get_or_create_installation_id())


def selected(store: GuardStore, harness: str = "codex") -> bool:
    row = store.resolve_policy_decision_lookup(harness, ARTIFACT, now=NOW)["decision"]
    return row is not None and row["action"] == "block"


def test_duplicate_human_names_do_not_select_either_installation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key_pair
) -> None:
    stores = [store_at(tmp_path / name, key_pair[1], "Office machine") for name in ("a", "b")]
    assert stores[0].get_or_create_installation_id() != stores[1].get_or_create_installation_id()
    bundle = bundle_for(key_pair, ["Office machine"])
    for store in stores:
        sync(store, bundle, monkeypatch)
        assert not selected(store)
        assert not selected(store, "cursor")


def test_renaming_to_a_target_installation_id_cannot_acquire_its_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key_pair
) -> None:
    target = store_at(tmp_path / "target", key_pair[1], "Office machine")
    other = store_at(tmp_path / "other", key_pair[1], target.get_or_create_installation_id())
    bundle = bundle_for(key_pair, [target.get_or_create_installation_id()])
    sync(target, bundle, monkeypatch)
    sync(other, bundle, monkeypatch)
    assert selected(target) and selected(target, "cursor")
    assert not selected(other)
    assert not selected(other, "cursor")


def test_renaming_preserves_target_but_reinstallation_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key_pair
) -> None:
    store = store_at(tmp_path / "target", key_pair[1], "Before rename")
    installation = store.get_or_create_installation_id()
    bundle = bundle_for(key_pair, [installation])
    sync(store, bundle, monkeypatch)
    assert selected(store)
    store.set_device_label("After rename", NOW)
    sync(store, bundle, monkeypatch)
    assert store.get_or_create_installation_id() == installation
    assert selected(store)
    store.rotate_installation_id(NOW)
    sync(store, bundle, monkeypatch)
    assert store.get_or_create_installation_id() != installation
    assert not selected(store)


@pytest.mark.parametrize("device_name", ["Shared computer", "installation-a"])
def test_legacy_materializer_also_rejects_display_name_authority(device_name: str) -> None:
    bundle = {
        "rules": [
            {
                "ruleId": "machine-only",
                "action": "block",
                "artifactId": ARTIFACT,
                "scope": {"devices": [device_name], "harnesses": ["codex"]},
            }
        ]
    }
    assert build_policy_bundle_decisions(bundle, device_id="installation-b", device_name=device_name) == []
    assert len(build_policy_bundle_decisions(bundle, device_id=device_name, device_name="Renamed")) == 1


def test_same_store_metadata_is_shared_by_runtime_instances(tmp_path: Path) -> None:
    home = tmp_path / "guard"
    first = GuardStore(home)
    first.set_device_label("Shared host", NOW)
    second = GuardStore(home)
    assert runner._guard_device_metadata(first) == runner._guard_device_metadata(second)
