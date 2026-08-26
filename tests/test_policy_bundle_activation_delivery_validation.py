"""Fail-closed Managed Controls activation delivery validation."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_bundle_activation import (
    encoded_delivery_acknowledgement,
    managed_delivery_matches_base,
)
from codex_plugin_scanner.guard.policy_bundle_delivery import effective_projection_digest
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import parse_managed_bundle

_VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json"
)


def _bundle() -> dict[str, object]:
    value = json.loads(_VECTOR_PATH.read_text())["bundle"]
    assert isinstance(value, dict)
    return value


def _authority(tmp_path: Path):
    store = GuardStore(tmp_path / "guard-home")
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
    return store.read_extension_control_authority_for_registry(registry)


def test_managed_delivery_base_match_rejects_missing_catalog_digest(tmp_path: Path) -> None:
    base = _authority(tmp_path)
    bundle = _bundle()

    assert not managed_delivery_matches_base(
        {
            "extensionAuthorityRevision": base.revision,
            "effectiveProjectionDigest": effective_projection_digest(base),
            "payloadHash": bundle["payloadHash"],
            "extensionProjectionDigest": "sha256:" + "0" * 64,
        },
        policy_bundle=bundle,
        policy=parse_managed_bundle(bundle),
        base_authority=base,
    )


def test_delivery_acknowledgement_rejects_missing_device_identity(tmp_path: Path) -> None:
    with (
        sqlite3.connect(":memory:") as connection,
        pytest.raises(ValueError, match="device identity"),
    ):
        encoded_delivery_acknowledgement(
            connection,
            delivery={},
            policy_bundle={},
            published_authority=_authority(tmp_path),
            observed_at="2026-08-26T00:00:00Z",
        )
