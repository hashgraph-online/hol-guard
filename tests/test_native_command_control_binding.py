"""Native binding parity, bounds, immutable generations, and authority MACs."""

from __future__ import annotations

import copy
import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_command_control_binding as binding_module
from codex_plugin_scanner.guard.native_command_control_binding import (
    NativeCommandProgramMetadata,
    build_native_command_control_binding,
    load_native_command_program_metadata,
    native_command_control_floor_mac,
    read_native_command_control_binding,
    validate_native_command_control_binding,
)
from codex_plugin_scanner.guard.native_policy_snapshot import (
    NativePolicySnapshotError,
    build_policy_snapshot_v3,
    native_policy_snapshot_v3,
    snapshot_bytes_v3,
)
from codex_plugin_scanner.guard.native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _digest_v3,
    _generation_floor_mac_v3,
    derive_native_policy_verifier_key,
)
from codex_plugin_scanner.guard.native_policy_snapshot_contract import _snapshot_integrity_mac_v3
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _authority_snapshot_v3
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _config


def _metadata() -> NativeCommandProgramMetadata:
    return NativeCommandProgramMetadata("a" * 64, BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest, "c" * 64)


def _layer(kind: ControlLayerKind, count: int = 1) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version="1.0.0",
        kind=kind,
        catalog_digest=_metadata().catalog_digest,
        global_lockdown=False,
        controls=tuple(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, f"command.example.target-{index}"), ControlState.DISABLED
            )
            for index in range(count)
        ),
    )


def _view(*, revision: int = 3, managed_revision: int = 7, count: int = 1) -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        revision,
        _metadata().catalog_digest,
        (_layer(ControlLayerKind.SIGNED_CLOUD, count), _layer(ControlLayerKind.LOCAL_ADMIN, count)),
        managed_revision,
    )


def _binding(**kwargs: int) -> dict[str, object]:
    return build_native_command_control_binding(
        ExtensionControlRuntimeSnapshot.from_authority_view(_view(**kwargs)), _metadata()
    )


def _snapshot(tmp_path: Path, **kwargs: object) -> dict[str, object]:
    return build_policy_snapshot_v3(
        config=_config(),
        guard_home=tmp_path,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=b"v" * 32,
        generation=1,
        issued_at_ms=1000,
        expires_at_ms=2000,
        **kwargs,
    )


def _program() -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "guard.native-command-program.v1",
        "compiler_version": 1,
        "semantic_profile": "cpython-3.12-ucd15",
        "authoring_semantics_digest": "f" * 64,
        "catalog_digest": _metadata().catalog_digest,
        "trust_digest": "c" * 64,
        "extensions": [],
        "rules": [],
        "nodes": {},
        "coverage": [],
        "matcher_families": {},
    }
    value["program_digest"] = hashlib.sha256(
        b"hol-guard.native-command-program.v1\0" + _canonical_json_bytes_v3(value)
    ).hexdigest()
    return value


@pytest.mark.parametrize("profile", (None, "cpython-3.13-ucd15", "cpython-3.12-ucd16", [], {}))
def test_artifact_requires_the_admitted_semantic_profile_even_with_a_valid_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: object
) -> None:
    value = _program()
    value.pop("program_digest")
    if profile is None:
        value.pop("semantic_profile")
    else:
        value["semantic_profile"] = profile
    value["program_digest"] = hashlib.sha256(
        b"hol-guard.native-command-program.v1\0" + _canonical_json_bytes_v3(value)
    ).hexdigest()
    artifact = tmp_path / "program.json"
    artifact.write_bytes(_canonical_json_bytes_v3(value))
    monkeypatch.setattr(binding_module, "_program_path", lambda: artifact)
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
        load_native_command_program_metadata()


def test_release_program_metadata_uses_the_compiled_semantic_profile() -> None:
    metadata = load_native_command_program_metadata()
    assert metadata.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert len(metadata.program_digest) == len(metadata.trust_digest) == 64


def test_projection_preserves_existing_effective_digest_and_complete_control_layers(tmp_path: Path) -> None:
    for count in (1, 512):
        snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(_view(count=count))
        binding = build_native_command_control_binding(snapshot, _metadata())
        assert binding["effective_digest"] == snapshot.effective_digest
        assert binding["revision"] == 3
        assert binding["managed_revision"] == 7
        assert [layer["kind"] for layer in binding["layers"]] == ["local-admin", "signed-cloud"]
        assert [len(layer["controls"]) for layer in binding["layers"]] == [count, count]
        validate_native_command_control_binding(binding)
        assert len(snapshot_bytes_v3(_snapshot(tmp_path, command_extensions=binding))) < 256 * 1024


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(schema="guard.native-command-control-binding.v2"),
        lambda value: value.update(program_digest="A" * 64),
        lambda value: value.update(catalog_digest="wrong"),
        lambda value: value.update(health={}),
        lambda value: value.update(health="allow"),
        lambda value: value.update(revision=True),
        lambda value: value.update(revision=-1),
        lambda value: value.update(managed_revision=2**64),
        lambda value: value.update(layers=None),
        lambda value: value["layers"].append(copy.deepcopy(value["layers"][0])),
        lambda value: value["layers"][0].update(global_lockdown=1),
        lambda value: value["layers"][0].update(catalog_digest="d" * 64),
        lambda value: value["layers"][0].update(kind="workspace"),
        lambda value: value["layers"][0].update(controls=[value["layers"][0]["controls"][0]] * 513),
        lambda value: value["layers"][0]["controls"].append(copy.deepcopy(value["layers"][0]["controls"][0])),
        lambda value: value["layers"][0]["controls"][0].update(state={}),
        lambda value: value["layers"][0]["controls"][0].update(state="allow"),
        lambda value: value["layers"][0]["controls"][0].update(target_id="command..invalid"),
        lambda value: value["layers"][0]["controls"][0].update(target_id="command.x.permission.y"),
        lambda value: value["layers"][0]["controls"][0].update(target_kind="permission"),
        lambda value: value["layers"][0]["controls"][0].update(state="enabled"),
    ],
)
def test_invalid_bindings_never_become_valid_policy(mutation) -> None:
    value = _binding()
    mutation(value)
    with pytest.raises(NativePolicySnapshotError):
        validate_native_command_control_binding(value)


def test_legacy_bytes_remain_identical_and_binding_changes_policy_digest_and_mac(tmp_path: Path) -> None:
    legacy = _snapshot(tmp_path)
    assert "command_extensions" not in legacy
    assert snapshot_bytes_v3(legacy) == snapshot_bytes_v3(_snapshot(tmp_path, command_extensions=None))
    binding = _binding()
    native = _snapshot(tmp_path, command_extensions=binding)
    assert native["config_digest"] == legacy["config_digest"]
    assert native["policy_digest"] != legacy["policy_digest"]
    assert native["integrity"]["mac"] != legacy["integrity"]["mac"]
    # The caller's mutable control mapping cannot change a signed generation.
    before = snapshot_bytes_v3(native)
    binding["revision"] = 100
    assert snapshot_bytes_v3(native) == before
    altered = copy.deepcopy(native)
    altered["command_extensions"] = _binding(revision=4)
    with pytest.raises(NativePolicySnapshotError, match="digest_mismatch"):
        snapshot_bytes_v3(altered)
    for binding_value in [None, {}, []]:
        altered = copy.deepcopy(legacy)
        altered["command_extensions"] = binding_value
        with pytest.raises(NativePolicySnapshotError):
            snapshot_bytes_v3(altered)


def test_generation_cache_tracks_control_digest_independently_of_config(tmp_path: Path) -> None:
    def emit(binding: dict[str, object]):
        return native_policy_snapshot_v3(
            config=_config(),
            guard_home=tmp_path,
            runtime_identity="a" * 64,
            rule_digest="b" * 64,
            policy_integrity_key=b"m" * 32,
            command_extensions=binding,
        )

    first = emit(_binding())
    assert emit(_binding()) == first
    second = emit(_binding(managed_revision=8))
    assert second["generation"] == first["generation"] + 1
    assert second["policy_digest"] != first["policy_digest"]
    assert second["config_digest"] == first["config_digest"]
    assert (
        _snapshot_integrity_mac_v3(second, derive_native_policy_verifier_key(b"m" * 32)) == second["integrity"]["mac"]
    )


def test_metadata_cache_rechecks_exact_bytes_even_when_file_size_and_mtime_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "program.json"
    artifact.write_bytes(_canonical_json_bytes_v3(_program()))
    monkeypatch.setattr(binding_module, "_program_path", lambda: artifact)
    first = load_native_command_program_metadata()
    assert load_native_command_program_metadata() is first
    timestamp = artifact.stat().st_mtime_ns
    artifact.write_bytes(artifact.read_bytes().replace(b'"trust_digest":"ccc', b'"trust_digest":"ddd'))
    os.utime(artifact, ns=(timestamp, timestamp))
    with pytest.raises(NativePolicySnapshotError, match="digest_mismatch"):
        load_native_command_program_metadata()


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{" * 10000,
        b"{}",
        b'{"schema":"a","schema":"b"}',
        b" " * (4 * 1024 * 1024 + 1),
    ],
)
def test_artifact_loader_rejects_oversize_invalid_and_duplicate_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
) -> None:
    artifact = tmp_path / "program.json"
    artifact.write_bytes(content)
    monkeypatch.setattr(binding_module, "_program_path", lambda: artifact)
    with pytest.raises(NativePolicySnapshotError):
        load_native_command_program_metadata()


def test_verified_reader_retains_independent_protected_revision_floors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path)
    monkeypatch.setattr(binding_module, "load_native_command_program_metadata", _metadata)
    current = _view()
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry, **_kwargs: current)
    first, runtime = read_native_command_control_binding(store)
    for candidate in [replace(current, revision=2), replace(current, managed_revision=6), replace(current, layers=())]:
        current = candidate
        with pytest.raises(NativePolicySnapshotError, match="revision_regressed"):
            read_native_command_control_binding(store, runtime)
        current = _view()
    current = replace(current, health=AuthorityHealth.TAMPERED, revision=0, managed_revision=0, layers=())
    degraded, runtime = read_native_command_control_binding(store, runtime)
    assert degraded["health"] == "tampered"
    assert degraded["revision"] == 0
    current = _view(managed_revision=6)
    with pytest.raises(NativePolicySnapshotError, match="revision_regressed"):
        read_native_command_control_binding(store, runtime)
    current = _view(managed_revision=8)
    recovered, _ = read_native_command_control_binding(store, runtime)
    assert recovered["revision"] == first["revision"]
    assert recovered["managed_revision"] == 8


def test_combined_authority_control_floor_uses_domain_separated_mac(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, command_extensions=_binding())
    floor = {key: snapshot["command_extensions"][key] for key in ("revision", "managed_revision", "effective_digest")}
    record = {
        "schema": "guard-policy-snapshot-authority.v3",
        "generation_floor": 1,
        "policy_digest": snapshot["policy_digest"],
        "snapshot": snapshot,
        "command_control_floor": floor,
        "floor_mac": native_command_control_floor_mac(1, snapshot["policy_digest"], floor, b"v" * 32),
    }
    assert _authority_snapshot_v3(record, _canonical_json_bytes_v3(record), b"v" * 32) == snapshot
    assert record["floor_mac"] != _generation_floor_mac_v3(1, snapshot["policy_digest"], b"v" * 32)
    record["command_control_floor"] = {**floor, "managed_revision": 9}
    with pytest.raises(NativePolicySnapshotError, match="cache_invalid"):
        _authority_snapshot_v3(record, _canonical_json_bytes_v3(record), b"v" * 32)
    legacy = _snapshot(tmp_path)
    assert native_command_control_floor_mac(1, legacy["policy_digest"], None, b"v" * 32) == _generation_floor_mac_v3(
        1,
        legacy["policy_digest"],
        b"v" * 32,
    )


def test_effective_control_digest_matches_existing_runtime_even_if_layer_order_changes() -> None:
    view = _view()
    first = build_native_command_control_binding(ExtensionControlRuntimeSnapshot.from_authority_view(view), _metadata())
    reordered = replace(view, layers=tuple(reversed(view.layers)))
    second = build_native_command_control_binding(
        ExtensionControlRuntimeSnapshot.from_authority_view(reordered), _metadata()
    )
    assert _digest_v3(first) == _digest_v3(second)
