"""Catalog capability transport and actual V4 publisher admission.

The resident transport here is the existing synthetic ACK fixture. These tests
do not claim a managed native consumer or advertise a production feature.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.native_command_control_binding import (
    NativeCommandProgramMetadata,
    build_native_command_control_binding,
)
from codex_plugin_scanner.guard.native_policy_authority_contract import NativeManagedPolicyAuthority
from codex_plugin_scanner.guard.native_runtime import _decode_capabilities
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ExtensionControlLayer
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from tests.test_native_policy_snapshot_v4_barrier import barrier as barrier

_CATALOG = "c" * 64


def _payload(features=()):
    return {
        "protocol_version": 1,
        "runtime_version": "3.0.1",
        "rule_digest": "b" * 64,
        "build_sha": "a" * 40,
        "target": "x86_64-linux",
        "features": list(features),
    }


@pytest.mark.parametrize("catalog", ["", "c" * 63, "c" * 65, "C" * 64, "g" * 64, True, 1, {}, [], " " + _CATALOG])
def test_malformed_catalog_cannot_become_executable_capability(catalog):
    assert _decode_capabilities({**_payload(), "extension_catalog_digest": catalog}) is None


def test_absent_catalog_preserves_legacy_capability_without_managed_support():
    capabilities = _decode_capabilities(_payload())
    assert capabilities is not None
    assert capabilities.extension_catalog_digest is None
    assert capabilities.features == ()
    assert _decode_capabilities({**_payload(), "extension_catalog_digest": None}) == capabilities


def _managed(barrier, catalog, *, feature=True):
    publisher, state = barrier
    managed = NativeManagedPolicyAuthority(
        revision=1, managed_revision=2, catalog_digest=_CATALOG, global_lockdown=True, controls=()
    )
    layer = ExtensionControlLayer(
        schema_version="1.0.0",
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=_CATALOG,
        global_lockdown=True,
        controls=(),
    )
    state.command_extensions = build_native_command_control_binding(
        ExtensionControlRuntimeSnapshot.from_authority_view(
            ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, _CATALOG, (layer,), 2)
        ),
        NativeCommandProgramMetadata("a" * 64, _CATALOG, "c" * 64),
    )
    state.command_extensions["authority"] = {
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "a" * 64,
        "recovery": None,
    }
    # The source capture and independently compiled command binding must
    # describe the same managed authority before runtime negotiation begins.
    source = {
        "kind": "managed-controls",
        "local_snapshot_digest": "b" * 64,
        **{
            field: state.command_extensions[field]
            for field in ("revision", "managed_revision", "catalog_digest", "effective_digest")
        },
    }
    state.inputs = replace(
        state.inputs,
        authority=replace(state.inputs.authority, managed=managed),
        _sources_json=json.dumps([*state.inputs.sources, source], sort_keys=True, separators=(",", ":")),
    )
    features = state.status.capabilities.features
    if feature:
        features += ("policy-managed-authority-v1",)
    payload = _payload(features)
    if catalog is not None:
        payload["extension_catalog_digest"] = catalog
    state.status.capabilities = _decode_capabilities(payload)
    assert state.status.capabilities is not None
    return publisher, state


def test_publisher_carries_exact_decoded_catalog_into_signed_snapshot(barrier):
    publisher, state = _managed(barrier, _CATALOG)
    publisher._publish_once()
    assert publisher.is_ready()
    assert len(state.calls) == 1
    managed = state.calls[0]["scoped_authority"]["managed"]
    assert managed["catalog_digest"] == _CATALOG
    assert managed["global_lockdown"] is True


@pytest.mark.parametrize("catalog", [None, "d" * 64])
def test_missing_or_changed_catalog_refuses_before_any_push(barrier, catalog):
    publisher, state = _managed(barrier, catalog)
    publisher._publish_once()
    assert publisher.last_error == "native_policy_authority_catalog_mismatch"
    assert not publisher.is_ready()
    assert state.calls == []


def test_catalog_identity_alone_does_not_negotiate_managed_semantics(barrier):
    publisher, state = _managed(barrier, _CATALOG, feature=False)
    publisher._publish_once()
    assert publisher.last_error == "native_policy_authority_capability_unsupported"
    assert not publisher.is_ready()
    assert state.calls == []
