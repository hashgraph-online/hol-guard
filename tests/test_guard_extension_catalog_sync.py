from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    EXTENSION_CATALOG_SCHEMA_VERSION,
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
    build_extension_catalog_wire,
    build_managed_controls_runtime_posture,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore


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


def test_production_runtime_sync_path_defaults_off_without_touching_local_authority(monkeypatch) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
        "GUARD_EXTENSION_FIRST_CONTROLS_UI",
    ):
        monkeypatch.delenv(name, raising=False)
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    assert guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T16:00:00Z",
    ) == {}
    assert store.reads == 0


def test_real_cloud_runtime_payload_advertises_only_enabled_protected_capabilities(
    tmp_path: Path,
    monkeypatch,
) -> None:
    for name in (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    ):
        monkeypatch.setenv(name, "true")
    payload = guard_runner_module._cloud_runtime_session_payload(
        GuardStore(tmp_path / "guard-home"),
        {
            "session_id": "runtime-session-1",
            "updated_at": "2026-08-25T16:00:00Z",
            "workspace": "local-machine",
        },
    )
    assert payload["extensionCatalogDigest"]
    assert payload["managedControlsCapabilities"] == ["extension-catalog.v1"]


def test_each_runtime_flag_removes_its_capability_without_touching_local_authority(monkeypatch) -> None:
    names = (
        "GUARD_EXTENSION_CATALOG_SYNC_V1",
        "GUARD_POLICY_EXTENSION_TARGETS_V1",
        "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
        "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
    )
    for name in names:
        monkeypatch.setenv(name, "true")
    store = FakePostureStore(ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 7, "a" * 64, ()))
    full = guard_runner_module._managed_controls_runtime_sync_posture(
        store,
        generated_at="2026-08-25T16:00:00Z",
    )
    assert set(full["managedControlsCapabilities"]) == set(MANAGED_CONTROLS_RUNTIME_CAPABILITIES)
    for disabled in names:
        monkeypatch.setenv(disabled, "false")
        posture = guard_runner_module._managed_controls_runtime_sync_posture(
            store,
            generated_at="2026-08-25T16:00:00Z",
        )
        capabilities = set(posture.get("managedControlsCapabilities", []))
        if disabled == "GUARD_EXTENSION_CATALOG_SYNC_V1":
            assert posture == {}
        elif disabled == "GUARD_MANAGED_EXTENSION_CONTROLS_V1":
            assert capabilities == {"extension-catalog.v1"}
        elif disabled == "GUARD_POLICY_EXTENSION_TARGETS_V1":
            assert "policy-extension-targets.v1" not in capabilities
            assert "managed-controls-atomic-apply.v1" not in capabilities
        else:
            assert "managed-controls-atomic-apply.v1" not in capabilities
        monkeypatch.setenv(disabled, "true")
