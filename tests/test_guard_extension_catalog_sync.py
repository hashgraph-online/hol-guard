from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    EXTENSION_CATALOG_SCHEMA_VERSION,
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
    build_extension_catalog_wire,
    build_managed_controls_runtime_posture,
    canonical_extension_catalog_json,
    catalog_digest_for_extensions,
    validate_extension_catalog_wire,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "contracts" / "managed-controls" / "v1"


def _shared_catalog_fixture() -> dict[str, object]:
    payload = json.loads((CONTRACT_ROOT / "extension-catalog.fixtures.json").read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


@dataclass(frozen=True)
class FakePermission:
    permission_id: str
    label: str
    configurable: bool
    risk_tier: str
    typed_capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class FakeExtension:
    extension_id: str
    version: str
    name: str
    source: str
    executables: tuple[str, ...]
    ecosystem_ids: tuple[str, ...]
    risk_classes: tuple[str, ...]
    delegated_protection: str | None
    permissions: tuple[FakePermission, ...]


@dataclass(frozen=True)
class FakeRegistry:
    extensions: tuple[FakeExtension, ...]


@dataclass
class FakePostureStore:
    authority: ExtensionControlAuthorityView
    reads: int = 0

    def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
        assert registry is BUILT_IN_COMMAND_EXTENSION_REGISTRY
        self.reads += 1
        return self.authority


def registry(*, reverse: bool = False) -> FakeRegistry:
    package = FakeExtension(
        extension_id="command.package-manager",
        version="1.0.0",
        name="Package manager",
        source="built-in",
        executables=("pnpm", "npm"),
        ecosystem_ids=("npm",),
        risk_classes=("supply_chain",),
        delegated_protection="package-firewall",
        permissions=(
            FakePermission(
                "command.package-manager.permission.package-protection",
                "Package protection",
                True,
                "high",
            ),
        ),
    )
    shell = FakeExtension(
        extension_id="command.shell",
        version="2.0.0",
        name="Shell",
        source="built-in",
        executables=("zsh", "bash", "bash"),
        ecosystem_ids=("posix",),
        risk_classes=("destructive", "execution"),
        delegated_protection=None,
        permissions=(
            FakePermission(
                "command.shell.permission.execute",
                "Execute shell",
                False,
                "critical",
                ("process.spawn", "process.exec"),
            ),
        ),
    )
    values = (package, shell)
    return FakeRegistry(tuple(reversed(values)) if reverse else values)


def test_wire_projection_is_order_independent_and_cross_language_canonical() -> None:
    first = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
    )
    second = build_extension_catalog_wire(
        registry(reverse=True),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:01Z",
    )
    assert first["catalogDigest"] == second["catalogDigest"]
    assert [item["id"] for item in first["extensions"]] == [
        "command.package-manager",
        "command.shell",
    ]
    canonical = json.dumps(first["extensions"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert first["catalogDigest"] == hashlib.sha256(canonical.encode()).hexdigest()


def test_wire_projection_contains_only_privacy_safe_catalog_metadata() -> None:
    payload = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
    )
    encoded = json.dumps(payload)
    for forbidden in (
        "description",
        "rules",
        "ruleIds",
        "exampleCommand",
        "projectMarkers",
        "referenceUrls",
        "sourcePath",
        "workingDirectory",
        "environment",
        "secrets",
    ):
        assert forbidden not in encoded
    assert payload["schemaVersion"] == EXTENSION_CATALOG_SCHEMA_VERSION
    assert payload["extensions"][0]["delegatedProtection"] == "package-firewall"


def test_wire_projection_sorts_set_like_fields_and_preserves_fixed_floors() -> None:
    payload = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
    )
    shell = payload["extensions"][1]
    assert shell["executables"] == ["bash", "zsh"]
    assert shell["riskClasses"] == ["destructive", "execution"]
    permission = shell["permissions"][0]
    assert permission["required"] is True
    assert permission["typedCapabilities"] == ["process.exec", "process.spawn"]


def test_runtime_posture_uses_cloud_capabilities_and_bounded_digests() -> None:
    posture = build_managed_controls_runtime_posture(
        catalog_digest="a" * 64,
        extension_authority_revision=7,
        effective_projection_digest="b" * 64,
    )
    assert posture["managedControlsCapabilities"] == list(MANAGED_CONTROLS_RUNTIME_CAPABILITIES)
    assert posture["extensionAuthorityRevision"] == 7
    assert posture["effectiveProjectionDigest"] == "b" * 64


@pytest.mark.parametrize(
    ("catalog_digest", "authority_revision", "effective_digest"),
    [
        ("not-a-digest", None, None),
        ("a" * 64, -1, None),
        ("a" * 64, 0, "not-a-digest"),
    ],
)
def test_runtime_posture_rejects_invalid_evidence(
    catalog_digest: str,
    authority_revision: int | None,
    effective_digest: str | None,
) -> None:
    with pytest.raises(ValueError):
        build_managed_controls_runtime_posture(
            catalog_digest=catalog_digest,
            extension_authority_revision=authority_revision,
            effective_projection_digest=effective_digest,
        )


def test_shared_catalog_fixture_is_schema_valid_and_canonically_executable() -> None:
    fixtures = _shared_catalog_fixture()
    schema = json.loads((CONTRACT_ROOT / "extension-catalog.schema.json").read_text(encoding="utf-8"))
    valid = fixtures["valid"]
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(valid)
    parsed = validate_extension_catalog_wire(valid)
    canonical = json.dumps(
        parsed["extensions"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == parsed["catalogDigest"]


def test_shared_catalog_unicode_uses_utf8_canonical_bytes() -> None:
    fixtures = _shared_catalog_fixture()
    valid = deepcopy(fixtures["valid"])
    assert isinstance(valid, dict)
    extensions = valid["extensions"]
    assert isinstance(extensions, list)
    extension = extensions[0]
    assert isinstance(extension, dict)
    extension["name"] = "Git protection — café"
    valid["catalogDigest"] = catalog_digest_for_extensions(extensions)
    parsed = validate_extension_catalog_wire(valid)
    assert "café" in json.dumps(parsed, ensure_ascii=False)


def test_shared_cross_language_canonicalization_vector_is_exact() -> None:
    vector = _shared_catalog_fixture()["canonicalizationVectors"][0]
    extensions = vector["extensions"]
    assert canonical_extension_catalog_json(extensions) == vector["canonicalJson"]
    assert catalog_digest_for_extensions(extensions) == vector["catalogDigest"]


def test_shared_invalid_generated_at_mutation_fails() -> None:
    fixture = _shared_catalog_fixture()
    mutation = fixture["invalidMutations"][0]
    payload = deepcopy(fixture["valid"])
    payload[mutation["field"]] = mutation["value"]
    with pytest.raises(ValueError, match="generatedAt"):
        validate_extension_catalog_wire(payload)


@pytest.mark.parametrize(
    "case",
    ("duplicateExtension", "duplicatePermission", "unknownField", "oversized", "privateField"),
)
def test_shared_invalid_catalog_cases_fail_behaviorally(case: str) -> None:
    fixtures = _shared_catalog_fixture()
    invalid = fixtures["invalid"]
    assert isinstance(invalid, dict)
    assert case in invalid
    payload = deepcopy(fixtures["valid"])
    assert isinstance(payload, dict)
    extensions = payload["extensions"]
    assert isinstance(extensions, list)
    extension = extensions[0]
    assert isinstance(extension, dict)
    permissions = extension["permissions"]
    assert isinstance(permissions, list)
    if case == "duplicateExtension":
        extensions.append(deepcopy(extension))
        payload["catalogDigest"] = catalog_digest_for_extensions(extensions)
    elif case == "duplicatePermission":
        permissions.append(deepcopy(permissions[0]))
        payload["catalogDigest"] = catalog_digest_for_extensions(extensions)
    elif case == "unknownField":
        payload["unexpected"] = True
    elif case == "oversized":
        payload["unexpected"] = "x" * 1_000_001
    else:
        payload["sourcePath"] = "/private/workspace"
    with pytest.raises(ValueError):
        validate_extension_catalog_wire(payload)


@pytest.mark.parametrize(
    ("field", "oversized_id"),
    (
        ("extension", "command." + ("a" * 300)),
        ("permission", "command.git.permission." + ("a" * 300)),
    ),
)
def test_catalog_validator_rejects_ids_over_shared_schema_limit(
    field: str,
    oversized_id: str,
) -> None:
    payload = deepcopy(_shared_catalog_fixture()["valid"])
    extensions = payload["extensions"]
    extension = extensions[0]
    if field == "extension":
        extension["id"] = oversized_id
        extension["permissions"][0]["id"] = f"{oversized_id}.permission.push"
    else:
        extension["permissions"][0]["id"] = oversized_id
    payload["catalogDigest"] = catalog_digest_for_extensions(extensions)
    with pytest.raises(ValueError, match="identity"):
        validate_extension_catalog_wire(payload)


def test_production_runtime_session_defaults_to_legacy_without_touching_local_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.delenv(name, raising=False)
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    assert (
        guard_runner_module._managed_controls_runtime_sync_posture(
            store,
            generated_at="2026-08-25T00:00:00Z",
        )
        == {}
    )
    assert store.reads == 0


def test_cloud_runtime_session_payload_carries_catalog_posture_on_real_sync_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    payload = guard_runner_module._cloud_runtime_session_payload(
        GuardStore(tmp_path / "guard-home"),
        {
            "session_id": "runtime-session-1",
            "updated_at": "2026-08-25T00:00:00Z",
            "workspace": "local-machine",
        },
    )
    assert payload["extensionCatalogDigest"]
    assert payload["extensionControlSchemaVersions"] == ["guard.extension-controls.v1"]
    assert payload["managedControlsCapabilities"] == ["extension-catalog.v1"]


def test_production_runtime_session_advertises_only_enabled_protected_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    posture = guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T00:00:00Z",
    )
    assert posture["extensionAuthorityRevision"] == 7
    assert posture["effectiveProjectionDigest"] is not None
    assert posture["managedControlsCapabilities"] == list(MANAGED_CONTROLS_RUNTIME_CAPABILITIES)
    assert store.reads == 1


@pytest.mark.parametrize(
    ("disabled_flag", "missing_capabilities"),
    (
        (
            "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
            {
                "extension-control-layer.v1",
                "policy-extension-targets.v1",
                "managed-controls-atomic-apply.v1",
            },
        ),
        (
            "GUARD_POLICY_EXTENSION_TARGETS_V1",
            {"policy-extension-targets.v1", "managed-controls-atomic-apply.v1"},
        ),
        ("GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1", {"managed-controls-atomic-apply.v1"}),
    ),
)
def test_production_runtime_session_downgrades_each_capability_independently(
    monkeypatch: pytest.MonkeyPatch,
    disabled_flag: str,
    missing_capabilities: set[str],
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    monkeypatch.setenv(disabled_flag, "false")
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    posture = guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T00:00:00Z",
    )
    advertised = set(posture["managedControlsCapabilities"])
    assert advertised == set(MANAGED_CONTROLS_RUNTIME_CAPABILITIES) - missing_capabilities


def test_production_runtime_session_downgrades_degraded_authority_to_catalog_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.TAMPERED, 7, "a" * 64, ()))
    posture = guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T00:00:00Z",
    )
    assert posture["extensionAuthorityRevision"] is None
    assert posture["effectiveProjectionDigest"] is None
    assert posture["managedControlsCapabilities"] == ["extension-catalog.v1"]
