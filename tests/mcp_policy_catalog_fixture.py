"""Admit authored MCP packs as signed fixture policy, before decision requests."""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from .test_native_pack_preparation import delivery as _build_delivery
from .test_native_pack_preparation import inventory as _build_inventory

_DELIVERY = []
_CATALOG_HOMES = {}


@pytest.fixture(scope="session")
def mcp_policy_inventory(tmp_path_factory):
    return _build_inventory.__wrapped__(tmp_path_factory)


@pytest.fixture
def mcp_policy_delivery(mcp_policy_inventory, tmp_path, monkeypatch):
    return _build_delivery.__wrapped__(mcp_policy_inventory, tmp_path, monkeypatch)


@pytest.fixture(autouse=True)
def native_mcp_catalog_admission(request):
    modules = {
        "test_guard_mcp_server_grants",
        "test_guard_mcp_mail_server_policy",
        "test_guard_ftp_mcp_contribution",
        "test_guard_gmail_mcp_contribution",
        "test_guard_remote_mcp_contributions",
        "test_guard_remote_mcp_endpoint_contract",
        "test_guard_remote_mcp_url_safety",
        "test_guard_remote_mcp_server_name_fallback",
        "test_guard_kranz_mcp_contribution",
        "test_guard_contributed_mcp_native",
        "test_guard_direct_mcp_contribution",
    }
    if request.module.__name__.rsplit(".", 1)[-1] not in modules:
        yield
        return
    _DELIVERY[:] = [request.getfixturevalue("mcp_policy_delivery")]
    yield
    _DELIVERY.clear()
    _CATALOG_HOMES.clear()


def admit_mcp_layers(store, layers):
    from codex_plugin_scanner.guard.catalog_delivery import preparation
    from codex_plugin_scanner.guard.native_command_control_authority import (
        AUTHORITY_FILE_NAME,
        AUTHORITY_MAX_BYTES,
        PACK_AUTHORITY_SCHEMA,
        ZERO_DIGEST,
        authority_binding,
        encode_authority,
    )
    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        hold_command_control_authority_lock,
        write_private_state,
    )
    from codex_plugin_scanner.guard.native_command_control_authority_store import _key
    from codex_plugin_scanner.guard.native_command_control_binding import build_native_command_control_binding
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
    from codex_plugin_scanner.guard.store import GuardStore

    from .mcp_policy_native_fixture import _ADMITTED, _BINDINGS, admit_mcp_policy_home

    key = (store.guard_home, layers)
    if key in _CATALOG_HOMES:
        store.guard_home = _CATALOG_HOMES[key]
        store.path = store.guard_home / "guard.db"
        return
    verified, _, engine = _DELIVERY[0]
    enabled = {
        control.target.target_id
        for layer in layers
        if layer.kind.value == "local-admin"
        for control in layer.controls
        if control.target.kind.value == "extension" and control.state.value != "disabled"
    }
    # Independent homes keep the synthetic scenarios from rewriting one
    # authenticated revision with a different collection or control digest.
    store.guard_home = store.guard_home / ("mcp-policy-" + uuid4().hex)
    store.path = store.guard_home / "guard.db"
    real = GuardStore(store.guard_home)
    provision_native_verifier_key_for_store(real)
    prepared = preparation.prepare(
        verified,
        enabled,
        store.guard_home / "native-runtime" / "command-packs",
        engine=engine,
    )
    rebound = tuple(replace(layer, catalog_digest=prepared.metadata.catalog_digest) for layer in layers)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=prepared.metadata.catalog_digest,
            layers=rebound,
        )
    )
    binding = build_native_command_control_binding(snapshot, prepared.metadata)
    marker = dict(
        schema=PACK_AUTHORITY_SCHEMA,
        epoch=1,
        mutation_revision=1,
        authority_key_id=ZERO_DIGEST,
        phase="committed",
        effective_digest=binding["effective_digest"],
        recovery=None,
        pack_program_digest=prepared.metadata.program_digest,
    )
    with hold_command_control_authority_lock(real.guard_home):
        write_private_state(
            real.guard_home, AUTHORITY_FILE_NAME, encode_authority(marker, _key(real)), AUTHORITY_MAX_BYTES
        )
    binding["authority"] = authority_binding(marker)
    _BINDINGS[store.guard_home] = binding
    _ADMITTED.pop(store.guard_home, None)
    admit_mcp_policy_home(store.guard_home)
    _CATALOG_HOMES[key] = store.guard_home
