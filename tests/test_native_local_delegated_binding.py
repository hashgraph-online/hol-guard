"""Bound local controls retain full source capture before a synthetic ACK.

These tests use actual enrollment, mutation proofs, storage and publication
encoding. The ACK transport is synthetic; installed resident execution remains
the separate native wheel probe's responsibility.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from ci.native_runtime.probe_installed_native_extensions import commit_controls, control, provision
from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.managed_controls_policy_fields_core import PACKAGE_FIREWALL_CAPABILITY
from codex_plugin_scanner.guard.native_policy_authority_contract import NativePolicyAuthorityCapabilities
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.native_policy_snapshot_v4_generation import reserve_snapshot_v4
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlState, ControlTargetKind
from codex_plugin_scanner.guard.store import GuardStore
from tests import native_managed_source_support
from tests.native_policy_snapshot_test_fixtures import _ack, _config, _status

_PASSWORD = "synthetic-installed-probe-password"


def _delegated_controls():
    return tuple(
        control(ControlTargetKind.PERMISSION, extension.permissions[0].permission_id, ControlState.DISABLED)
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.delegated_protection == "package-firewall"
    )


@pytest.fixture
def local_controls(tmp_path: Path):
    store = GuardStore(tmp_path / "guard")
    update_settings(
        store.guard_home,
        {"enabled": True, "new_password": _PASSWORD, "confirm_password": _PASSWORD, "cooldown_seconds": 0},
    )
    provision(store)
    assert store._policy_integrity_secret_material(create=True)[0] is not None
    calls = []

    def client(**kwargs):
        calls.append(json.loads(kwargs["payload"])["request"]["snapshot"])
        return _ack(kwargs["payload"])

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status, client_request=client)
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        old_binding = publisher._compiled_command_extensions()
        controls = _delegated_controls()
        assert len(controls) == 8
        revision = commit_controls(store, _PASSWORD, controls)
        assert not publisher.is_ready()
        yield store, publisher, calls, old_binding, revision
    finally:
        publisher.close()


def test_local_delegated_controls_reach_v3_with_the_complete_matching_binding(local_controls):
    store, publisher, calls, _, revision = local_controls
    binding = publisher._compiled_command_extensions()
    inputs = read_native_policy_authority_inputs(store, now=time.time(), command_extensions=binding)
    assert inputs.authority.managed is not None
    expected = {item.target.target_id for item in _delegated_controls()}
    assert {item.target_id for item in inputs.authority.managed.controls} == expected
    assert len(inputs.sources) == 1
    assert inputs.sources[0]["requires_native_command_binding"] is True
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    assert len(calls) == 2
    snapshot = publisher.current_snapshot()
    assert snapshot is not None and snapshot["version"] == 3
    assert snapshot["command_extensions"] == binding and binding["revision"] == revision
    assert "scoped_authority" not in snapshot
    assert {item["target_id"] for layer in binding["layers"] for item in layer["controls"]} == expected


@pytest.mark.parametrize("fault", ["missing", "stale", "no-authority"])
def test_delegated_capture_never_substitutes_an_unbound_or_stale_projection(local_controls, fault):
    store, publisher, _, old_binding, _ = local_controls
    binding = publisher._compiled_command_extensions()
    if fault == "missing":
        binding = None
    elif fault == "stale":
        binding = old_binding
    else:
        binding.pop("authority")
    reason = "bundle_semantics_unsupported" if fault == "missing" else "command_control_binding_changed"
    with pytest.raises(NativePolicySnapshotError, match=reason):
        read_native_policy_authority_inputs(store, now=time.time(), command_extensions=binding)
    assert not publisher.is_ready()


def test_bound_delegated_input_cannot_be_reserved_as_supported_scoped_v4(local_controls, tmp_path: Path):
    store, publisher, calls, _, _ = local_controls
    binding = publisher._compiled_command_extensions()
    inputs = read_native_policy_authority_inputs(store, now=time.time(), command_extensions=binding)
    scoped_home = tmp_path / "scoped-candidate"
    with pytest.raises(NativePolicySnapshotError, match="bundle_semantics_unsupported"):
        reserve_snapshot_v4(
            config=_config(),
            guard_home=scoped_home,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            master_key=b"k" * 32,
            inputs=inputs,
            capabilities=NativePolicyAuthorityCapabilities(
                4, SCOPED_PUBLISH_FEATURES | {"policy-managed-authority-v1"}, binding["catalog_digest"]
            ),
            issued_at_ms=int(time.time() * 1000),
            command_extensions=binding,
        )
    assert not scoped_home.exists()
    assert len(calls) == 1 and not publisher.is_ready()


def test_signed_delegated_controls_are_refused_even_with_a_current_command_binding(tmp_path, monkeypatch):
    permission = _delegated_controls()[0].target.target_id
    monkeypatch.setattr(native_managed_source_support, "PERMISSION", permission)
    monkeypatch.setattr(
        native_managed_source_support,
        "CAPABILITIES",
        native_managed_source_support.CAPABILITIES | {PACKAGE_FIREWALL_CAPABILITY},
    )
    store = native_managed_source_support.managed_store(tmp_path, monkeypatch, scoped=False)
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=_status)
    try:
        binding = publisher._compiled_command_extensions()
        with pytest.raises(NativePolicySnapshotError, match="bundle_semantics_unsupported"):
            read_native_policy_authority_inputs(store, now=time.time(), command_extensions=binding)
    finally:
        publisher.close()
