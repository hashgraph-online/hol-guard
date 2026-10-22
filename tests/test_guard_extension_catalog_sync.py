from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    EXTENSION_CATALOG_SCHEMA_VERSION,
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
    ExtensionCatalogLimitError,
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
from codex_plugin_scanner.guard.runtime.extension_control_limits import CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_cloud_helpers import native_bridge as native_bridge
from tests.native_cloud_helpers import prepare_native

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
    guard_home: Path = Path("/synthetic-guard-home")

    def read_extension_control_authority_for_registry(
        self, registry: object, **_kwargs
    ) -> ExtensionControlAuthorityView:
        assert registry is BUILT_IN_COMMAND_EXTENSION_REGISTRY
        self.reads += 1
        return self.authority


@pytest.fixture
def prepared_posture_catalog(monkeypatch: pytest.MonkeyPatch, native_bridge) -> None:
    from codex_plugin_scanner.guard.runtime import extension_catalog_pages as pages
    from codex_plugin_scanner.guard.runtime import managed_controls_sync as controls

    # Synthetic active-authority adapter for these catalog/session wire units.
    monkeypatch.setattr(controls, "current_catalog_registry", lambda _: BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    def prepared(_home, *, registry, guard_version, generated_at):
        return prepare_native(
            values=[pages._raw_extension(item) for item in registry.extensions],
            enforcement_digest=registry.catalog_digest,
            guard_version=guard_version,
            generated_at=generated_at,
        )

    monkeypatch.setattr(pages, "prepare_installed_catalog_view", prepared)


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


# Pure projection, canonicalization, and refusal cases live with the native
# owner in rust/crates/guard-command/src/cloud_catalog_wire_v1_tests.rs.
# These tests pin the Python glue: transport, field order, and error classes.
_REGISTRY_CATALOG_DIGEST = "a7caf8d1c4eba405cece0b9ad78ad43b85458b5bb0f78855b42a0919655c3d1a"


def test_native_wire_projection_keeps_digest_and_field_order(tmp_path: Path) -> None:
    home = GuardStore(tmp_path / "guard-home").guard_home
    first = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
        guard_home=home,
    )
    second = build_extension_catalog_wire(
        registry(reverse=True),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:01Z",
        guard_home=home,
    )
    assert first["catalogDigest"] == second["catalogDigest"] == _REGISTRY_CATALOG_DIGEST
    assert first["schemaVersion"] == EXTENSION_CATALOG_SCHEMA_VERSION
    assert list(first) == [
        "schemaVersion",
        "catalogDigest",
        "guardVersion",
        "controlSchemaVersion",
        "generatedAt",
        "limits",
        "extensions",
    ]
    assert list(first["limits"]) == [
        "maxExtensions",
        "maxPermissionsPerExtension",
        "maxPayloadBytes",
        "maxStringLength",
    ]
    shell = first["extensions"][1]
    assert list(shell)[:4] == ["id", "version", "name", "source"]
    assert shell["executables"] == ["bash", "zsh"]
    assert list(shell["permissions"][0]) == [
        "id",
        "name",
        "configurable",
        "required",
        "riskClasses",
        "typedCapabilities",
    ]
    canonical = json.dumps(first["extensions"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert canonical_extension_catalog_json(first["extensions"], guard_home=home) == canonical
    assert hashlib.sha256(canonical.encode()).hexdigest() == first["catalogDigest"]
    assert catalog_digest_for_extensions(first["extensions"], guard_home=home) == first["catalogDigest"]
    assert validate_extension_catalog_wire(first, guard_home=home) == first


def test_native_wire_refusals_keep_their_exception_classes(tmp_path: Path) -> None:
    home = GuardStore(tmp_path / "guard-home").guard_home
    payload = deepcopy(_shared_catalog_fixture()["valid"])
    payload["generatedAt"] = "not-a-date"
    with pytest.raises(ValueError, match=r"^Invalid Extension catalog generatedAt$") as refused:
        validate_extension_catalog_wire(payload, guard_home=home)
    assert not isinstance(refused.value, ExtensionCatalogLimitError)
    payload["unexpected"] = "x" * (CLOUD_V1_MAX_CATALOG_PAYLOAD_BYTES + 1)
    with pytest.raises(ExtensionCatalogLimitError, match=r"^Extension catalog payload limit exceeded$"):
        validate_extension_catalog_wire(payload, guard_home=home)
    with pytest.raises(ValueError, match=r"^guard_version and generated_at are required$"):
        build_extension_catalog_wire(registry(), guard_version=" ", generated_at="2026-08-23T12:00:00Z")


def test_runtime_posture_uses_cloud_capabilities_and_bounded_digests() -> None:
    posture = build_managed_controls_runtime_posture(
        catalog_digest="a" * 64,
        extension_authority_revision=7,
        effective_projection_digest="sha256:" + "b" * 64,
    )
    assert posture["managedControlsCapabilities"] == list(MANAGED_CONTROLS_RUNTIME_CAPABILITIES)
    assert posture["extensionAuthorityRevision"] == 7
    assert posture["effectiveProjectionDigest"] == "sha256:" + "b" * 64


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


def test_shared_catalog_fixture_is_schema_valid_and_canonically_executable(tmp_path: Path) -> None:
    fixtures = _shared_catalog_fixture()
    schema = json.loads((CONTRACT_ROOT / "extension-catalog.schema.json").read_text(encoding="utf-8"))
    valid = fixtures["valid"]
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(valid)
    parsed = validate_extension_catalog_wire(valid, guard_home=tmp_path)
    canonical = json.dumps(
        parsed["extensions"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == parsed["catalogDigest"]


def test_shared_catalog_schema_requires_the_semantic_identity_validator() -> None:
    schema = json.loads((CONTRACT_ROOT / "extension-catalog.schema.json").read_text(encoding="utf-8"))

    assert schema["x-hol-guard-semantic-validator"] == {
        "id": "validate-extension-catalog-wire-v1",
        "required": True,
        "rules": [
            "unique-extension-id",
            "globally-unique-permission-id",
            "replacement-target-exists",
            "replacement-target-is-not-self",
        ],
    }


def test_shared_catalog_schema_rejects_replacement_on_active_extension() -> None:
    fixtures = _shared_catalog_fixture()
    invalid = deepcopy(fixtures["valid"])
    extension = invalid["extensions"][0]
    extension["deprecated"] = False
    extension["replacementId"] = "command.package-manager"
    schema = json.loads((CONTRACT_ROOT / "extension-catalog.schema.json").read_text(encoding="utf-8"))

    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(invalid)


@pytest.mark.parametrize("field", ["riskClasses", "typedCapabilities"])
def test_shared_catalog_schema_rejects_empty_permission_capability_values(field: str) -> None:
    fixtures = _shared_catalog_fixture()
    invalid = deepcopy(fixtures["valid"])
    assert isinstance(invalid, dict)
    extensions = invalid["extensions"]
    assert isinstance(extensions, list)
    extension = extensions[0]
    assert isinstance(extension, dict)
    permissions = extension["permissions"]
    assert isinstance(permissions, list)
    permission = permissions[0]
    assert isinstance(permission, dict)
    permission[field] = [""]
    schema = json.loads((CONTRACT_ROOT / "extension-catalog.schema.json").read_text(encoding="utf-8"))

    with pytest.raises(ValidationError):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(invalid)


def test_production_runtime_session_defaults_to_legacy_without_touching_local_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
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
    prepared_posture_catalog: None,
) -> None:
    monkeypatch.setenv("GUARD_EXTENSION_CATALOG_SYNC_V1", "true")
    # This is a session/catalog wire test; native package-manager inventory is
    # qualified separately and is not required by the synthetic sender fixture.
    monkeypatch.setattr(guard_runner_module, "_cloud_package_manager_coverage", lambda *args, **kwargs: {})
    payload = guard_runner_module._cloud_runtime_session_payload(
        GuardStore(tmp_path / "guard-home"),
        {
            "session_id": "runtime-session-1",
            "updated_at": "2026-08-25T00:00:00Z",
            "workspace": "local-machine",
        },
    )
    assert payload["extensionCatalogDigest"]
    # A complete transport alone does not qualify native policy application.
    assert payload["extensionControlSchemaVersions"] == ["guard.extension-controls.v1"]
    assert payload["extensionCatalogViewDigest"] != payload["extensionCatalogDigest"]
    assert payload["managedControlsCapabilities"] == ["extension-catalog.v2"]


def test_production_runtime_session_requires_completed_native_policy_observation(
    monkeypatch: pytest.MonkeyPatch,
    prepared_posture_catalog: None,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    ):
        monkeypatch.setenv(name, "true")
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    posture = guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T00:00:00Z",
    )
    assert "extensionAuthorityRevision" not in posture
    assert "effectiveProjectionDigest" not in posture
    assert posture["managedControlsCapabilities"] == ["extension-catalog.v2"]
    assert store.reads == 0


@pytest.mark.parametrize(
    ("disabled_flag", "missing_capabilities"),
    (
        (
            "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
            {
                "extension-control-layer.v1",
                "policy-extension-targets.v1",
                "managed-controls-atomic-apply.v1",
                "custom-extension-continuity.v2",
            },
        ),
        (
            "GUARD_POLICY_EXTENSION_TARGETS_V1",
            {
                "policy-extension-targets.v1",
                "managed-controls-atomic-apply.v1",
                "custom-extension-continuity.v2",
            },
        ),
        (
            "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
            {"managed-controls-atomic-apply.v1", "custom-extension-continuity.v2"},
        ),
    ),
)
def test_production_runtime_session_downgrades_each_capability_independently(
    monkeypatch: pytest.MonkeyPatch,
    disabled_flag: str,
    missing_capabilities: set[str],
    prepared_posture_catalog: None,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    ):
        monkeypatch.setenv(name, "true")
    monkeypatch.setenv(disabled_flag, "false")
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    posture = guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T00:00:00Z",
    )
    advertised = set(posture["managedControlsCapabilities"])
    # Individual opt-ins cannot override a missing authenticated native view.
    assert advertised == {"extension-catalog.v2"}


def test_production_runtime_session_downgrades_degraded_authority_to_catalog_only(
    monkeypatch: pytest.MonkeyPatch,
    prepared_posture_catalog: None,
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
    assert posture.get("extensionAuthorityRevision") is None
    assert posture.get("effectiveProjectionDigest") is None
    assert posture["managedControlsCapabilities"] == ["extension-catalog.v2"]


def test_oversized_native_request_is_a_catalog_limit_before_any_resident_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.runtime import extension_catalog_pages, extension_catalog_sync

    monkeypatch.setattr(
        extension_catalog_pages, "native_call", lambda *_args, **_kwargs: pytest.fail("oversized request was sent")
    )
    with pytest.raises(ExtensionCatalogLimitError, match="native wire limits"):
        extension_catalog_sync.native_wire_call("build", guard_home=tmp_path, raw_extensions=["x" * (4 * 1024 * 1024)])
    # Non-ASCII text grows to six-byte escapes on the transport, so it counts that way too.
    with pytest.raises(ExtensionCatalogLimitError, match="native wire limits"):
        extension_catalog_sync.native_wire_call("build", guard_home=tmp_path, raw_extensions=["\u00e9" * (1024 * 1024)])
