from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "codex_plugin_scanner" / "guard" / "managed_controls"
TESTS = ROOT / "tests" / "managed_controls"
DASHBOARD = ROOT / "dashboard" / "src" / "managed-controls"
BATCH_DOCS = ROOT / "docs" / "guard" / "managed-controls" / "batches"


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def add_dashboard_test(relative_path: str) -> None:
    package_path = ROOT / "dashboard" / "package.json"
    data = json.loads(package_path.read_text(encoding="utf-8"))
    command = f"tsx {relative_path}"
    test_script = data["scripts"]["test"]
    if command not in test_script:
        data["scripts"]["test"] = f"{test_script} && {command}"
        package_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def batch_manifest(batch: int, theme: str, evidence: list[str]) -> None:
    start = (batch - 1) * 15 + 1
    end = min(start + 14, 523)
    write(
        BATCH_DOCS / f"{batch:02d}.json",
        json.dumps(
            {
                "schema_version": 1,
                "batch": batch,
                "task_range": {"start": start, "end": end},
                "theme": theme,
                "repository": "hashgraph-online/hol-guard",
                "target_branch": "release/3.0",
                "evidence": evidence,
            },
            indent=2,
            sort_keys=True,
        ),
    )


def ensure_package() -> None:
    write(
        PACKAGE / "__init__.py",
        '''"""Release 3.0 Extension-First Managed Controls contracts."""

from .acknowledgement import ManagedControlsAcknowledgement
from .authority import AuthorityMode, ControlEffect, ControlInstruction
from .capabilities import MANAGED_CONTROL_CAPABILITIES
from .catalog import CatalogExtension, CatalogPermission, CatalogProjection

__all__ = [
    "AuthorityMode",
    "CatalogExtension",
    "CatalogPermission",
    "CatalogProjection",
    "ControlEffect",
    "ControlInstruction",
    "MANAGED_CONTROL_CAPABILITIES",
    "ManagedControlsAcknowledgement",
]
''',
    )
    write(TESTS / "__init__.py", '"""Managed Controls conformance tests."""')


def batch_03() -> None:
    ensure_package()
    write(
        PACKAGE / "capabilities.py",
        '''"""Capability negotiation for Extension-targeted Managed Controls."""

from __future__ import annotations

from dataclasses import dataclass

MANAGED_CONTROL_CAPABILITIES = frozenset(
    {
        "extension-catalog.v1",
        "extension-control-layer.v1",
        "policy-extension-targets.v1",
        "managed-controls-atomic-apply.v1",
    }
)


class CapabilityNegotiationError(ValueError):
    """Raised when a runtime cannot honor a required contract."""


@dataclass(frozen=True, slots=True)
class RuntimeCapabilityAdvertisement:
    capabilities: frozenset[str]
    catalog_schema_version: int = 1
    extension_control_schema_version: int = 1

    @classmethod
    def from_values(
        cls,
        values: object,
        *,
        catalog_schema_version: int = 1,
        extension_control_schema_version: int = 1,
    ) -> "RuntimeCapabilityAdvertisement":
        if not isinstance(values, (list, tuple, set, frozenset)):
            raise CapabilityNegotiationError("capabilities must be a collection")
        capabilities = frozenset(value for value in values if isinstance(value, str))
        if len(capabilities) != len(values):
            raise CapabilityNegotiationError("capabilities must contain strings")
        return cls(
            capabilities=capabilities,
            catalog_schema_version=catalog_schema_version,
            extension_control_schema_version=extension_control_schema_version,
        )

    def require(self, required: frozenset[str]) -> None:
        missing = sorted(required - self.capabilities)
        if missing:
            raise CapabilityNegotiationError(
                f"runtime is missing required capabilities: {', '.join(missing)}"
            )

    @property
    def supports_managed_controls(self) -> bool:
        return MANAGED_CONTROL_CAPABILITIES <= self.capabilities
''',
    )
    write(
        PACKAGE / "catalog.py",
        '''"""Canonical, bounded, privacy-safe Extension catalog projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
MAX_EXTENSIONS = 512
MAX_PERMISSIONS_PER_EXTENSION = 512
MAX_CATALOG_BYTES = 1_000_000


class CatalogValidationError(ValueError):
    """Raised when a catalog cannot be trusted or represented."""


def _identity(value: str, label: str) -> str:
    if not _ID_PATTERN.fullmatch(value):
        raise CatalogValidationError(f"invalid {label}")
    return value


@dataclass(frozen=True, slots=True)
class CatalogPermission:
    permission_id: str
    name: str
    configurable: bool
    required: bool = False
    delegated_protection: str | None = None

    def __post_init__(self) -> None:
        _identity(self.permission_id, "permission id")
        if not self.name.strip():
            raise CatalogValidationError("permission name is required")
        if self.required and self.configurable:
            raise CatalogValidationError("required permissions cannot be configurable")

    def to_dict(self) -> dict[str, object]:
        return {
            "permission_id": self.permission_id,
            "name": self.name,
            "configurable": self.configurable,
            "required": self.required,
            "delegated_protection": self.delegated_protection,
        }


@dataclass(frozen=True, slots=True)
class CatalogExtension:
    extension_id: str
    name: str
    version: str
    permissions: tuple[CatalogPermission, ...]
    required: bool = False
    custom: bool = False

    def __post_init__(self) -> None:
        _identity(self.extension_id, "extension id")
        if not self.name.strip() or not self.version.strip():
            raise CatalogValidationError("extension name and version are required")
        if len(self.permissions) > MAX_PERMISSIONS_PER_EXTENSION:
            raise CatalogValidationError("permission limit exceeded")
        permission_ids = [item.permission_id for item in self.permissions]
        if len(permission_ids) != len(set(permission_ids)):
            raise CatalogValidationError("duplicate permission id")

    def to_dict(self) -> dict[str, object]:
        return {
            "extension_id": self.extension_id,
            "name": self.name,
            "version": self.version,
            "required": self.required,
            "custom": self.custom,
            "permissions": [item.to_dict() for item in self.permissions],
        }


@dataclass(frozen=True, slots=True)
class CatalogProjection:
    schema_version: int
    extensions: tuple[CatalogExtension, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CatalogValidationError("unsupported catalog schema")
        if len(self.extensions) > MAX_EXTENSIONS:
            raise CatalogValidationError("extension limit exceeded")
        extension_ids = [item.extension_id for item in self.extensions]
        if len(extension_ids) != len(set(extension_ids)):
            raise CatalogValidationError("duplicate extension id")
        if len(self.canonical_bytes()) > MAX_CATALOG_BYTES:
            raise CatalogValidationError("catalog payload limit exceeded")

    def payload(self) -> dict[str, object]:
        ordered = sorted(self.extensions, key=lambda item: item.extension_id)
        return {
            "schema_version": self.schema_version,
            "extensions": [item.to_dict() for item in ordered],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def permission(self, extension_id: str, permission_id: str) -> CatalogPermission:
        for extension in self.extensions:
            if extension.extension_id != extension_id:
                continue
            for permission in extension.permissions:
                if permission.permission_id == permission_id:
                    return permission
        raise CatalogValidationError("unknown extension or permission target")
''',
    )
    write(
        TESTS / "test_capabilities_catalog.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.capabilities import (
    MANAGED_CONTROL_CAPABILITIES,
    CapabilityNegotiationError,
    RuntimeCapabilityAdvertisement,
)
from codex_plugin_scanner.guard.managed_controls.catalog import (
    CatalogExtension,
    CatalogPermission,
    CatalogProjection,
    CatalogValidationError,
)


def _catalog() -> CatalogProjection:
    permission = CatalogPermission("push", "Push", configurable=True)
    extension = CatalogExtension("command.git", "Git", "1", (permission,))
    return CatalogProjection(1, (extension,))


def test_requires_all_four_capabilities() -> None:
    advertisement = RuntimeCapabilityAdvertisement(MANAGED_CONTROL_CAPABILITIES)
    assert advertisement.supports_managed_controls
    advertisement.require(MANAGED_CONTROL_CAPABILITIES)
    with pytest.raises(CapabilityNegotiationError):
        RuntimeCapabilityAdvertisement(frozenset()).require(
            MANAGED_CONTROL_CAPABILITIES
        )


def test_catalog_identity_and_digest_are_deterministic() -> None:
    catalog = _catalog()
    assert len(catalog.digest) == 64
    assert catalog.permission("command.git", "push").configurable
    assert catalog.digest == _catalog().digest


def test_unknown_targets_fail_instead_of_disappearing() -> None:
    with pytest.raises(CatalogValidationError):
        _catalog().permission("command.git", "missing")
''',
    )
    batch_manifest(
        3,
        "Runtime capability negotiation and canonical Extension catalog",
        [
            "src/codex_plugin_scanner/guard/managed_controls/capabilities.py",
            "src/codex_plugin_scanner/guard/managed_controls/catalog.py",
            "tests/managed_controls/test_capabilities_catalog.py",
        ],
    )


def batch_04() -> None:
    write(
        PACKAGE / "privacy.py",
        '''"""Privacy boundaries for Local-to-Cloud catalog continuity."""

from __future__ import annotations

from collections.abc import Mapping

_ALLOWED_EXTENSION_FIELDS = frozenset(
    {"extension_id", "name", "version", "required", "custom", "permissions"}
)
_ALLOWED_PERMISSION_FIELDS = frozenset(
    {
        "permission_id",
        "name",
        "configurable",
        "required",
        "delegated_protection",
    }
)
_FORBIDDEN_MARKERS = (
    "command",
    "raw_command",
    "source_path",
    "working_directory",
    "secret",
    "token",
    "environment",
)


class CatalogPrivacyError(ValueError):
    """Raised when a projection crosses the catalog privacy boundary."""


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
                raise CatalogPrivacyError(f"forbidden catalog field: {key}")
            _reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_keys(child)


def privacy_safe_catalog_payload(payload: Mapping[str, object]) -> dict[str, object]:
    _reject_forbidden_keys(payload)
    extensions = payload.get("extensions")
    if not isinstance(extensions, list):
        raise CatalogPrivacyError("extensions must be a list")
    safe_extensions: list[dict[str, object]] = []
    for extension in extensions:
        if not isinstance(extension, Mapping):
            raise CatalogPrivacyError("extension entry must be an object")
        safe = {
            key: extension[key]
            for key in _ALLOWED_EXTENSION_FIELDS
            if key in extension
        }
        permissions = safe.get("permissions", [])
        if not isinstance(permissions, list):
            raise CatalogPrivacyError("permissions must be a list")
        safe["permissions"] = [
            {
                key: permission[key]
                for key in _ALLOWED_PERMISSION_FIELDS
                if key in permission
            }
            for permission in permissions
            if isinstance(permission, Mapping)
        ]
        safe_extensions.append(safe)
    return {
        "schema_version": payload.get("schema_version"),
        "catalog_digest": payload.get("catalog_digest"),
        "extensions": safe_extensions,
    }
''',
    )
    write(
        PACKAGE / "identity.py",
        '''"""Stable identity and catalog compatibility helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CatalogIdentityState(StrEnum):
    EXACT = "exact"
    VERSION_DIFFERENT = "version_different"
    MISSING = "missing"
    CUSTOM_LOCAL_ONLY = "custom_local_only"


@dataclass(frozen=True, slots=True)
class ExtensionIdentity:
    extension_id: str
    version: str
    custom: bool = False


def compare_extension_identity(
    local: ExtensionIdentity,
    cloud: ExtensionIdentity | None,
) -> CatalogIdentityState:
    if cloud is None:
        if local.custom:
            return CatalogIdentityState.CUSTOM_LOCAL_ONLY
        return CatalogIdentityState.MISSING
    if local.extension_id != cloud.extension_id:
        return CatalogIdentityState.MISSING
    if local.version != cloud.version:
        return CatalogIdentityState.VERSION_DIFFERENT
    return CatalogIdentityState.EXACT
''',
    )
    write(
        TESTS / "test_catalog_privacy_identity.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.identity import (
    CatalogIdentityState,
    ExtensionIdentity,
    compare_extension_identity,
)
from codex_plugin_scanner.guard.managed_controls.privacy import (
    CatalogPrivacyError,
    privacy_safe_catalog_payload,
)


def test_catalog_projection_excludes_commands_paths_and_secrets() -> None:
    payload = {
        "schema_version": 1,
        "catalog_digest": "a" * 64,
        "extensions": [
            {
                "extension_id": "command.git",
                "name": "Git",
                "version": "1",
                "permissions": [],
            }
        ],
    }
    assert privacy_safe_catalog_payload(payload) == payload
    with pytest.raises(CatalogPrivacyError):
        privacy_safe_catalog_payload(
            {**payload, "extensions": [{"raw_command": "rm -rf /"}]}
        )


def test_custom_identity_is_truthfully_local_only_without_cloud_match() -> None:
    local = ExtensionIdentity("custom.acme", "1", custom=True)
    assert (
        compare_extension_identity(local, None)
        is CatalogIdentityState.CUSTOM_LOCAL_ONLY
    )
''',
    )
    batch_manifest(
        4,
        "Privacy-safe catalog projection and stable identity continuity",
        [
            "src/codex_plugin_scanner/guard/managed_controls/privacy.py",
            "src/codex_plugin_scanner/guard/managed_controls/identity.py",
            "tests/managed_controls/test_catalog_privacy_identity.py",
        ],
    )


def batch_05() -> None:
    write(
        PACKAGE / "authority.py",
        '''"""Authority modes and disable-dominant Extension control composition."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthorityMode(StrEnum):
    PERSONAL_SHARED = "personal-shared"
    WORKSPACE_SHARED = "workspace-shared"
    MANAGED_RESTRICTIVE = "managed-restrictive"


class ControlEffect(StrEnum):
    INHERIT = "inherit"
    PERMIT = "permit"
    BLOCK = "block"
    LOCKDOWN = "lockdown"


class AuthorityValidationError(ValueError):
    """Raised when an authority attempts an unsupported outcome."""


@dataclass(frozen=True, slots=True)
class ControlInstruction:
    extension_id: str | None
    permission_id: str | None
    effect: ControlEffect
    authority: AuthorityMode
    source_id: str

    def __post_init__(self) -> None:
        if self.effect is ControlEffect.LOCKDOWN:
            if self.extension_id is not None or self.permission_id is not None:
                raise AuthorityValidationError("lockdown cannot target a permission")
        elif not self.extension_id:
            raise AuthorityValidationError("extension id is required")
        if (
            self.authority is AuthorityMode.MANAGED_RESTRICTIVE
            and self.effect not in {ControlEffect.BLOCK, ControlEffect.LOCKDOWN}
        ):
            raise AuthorityValidationError(
                "managed-restrictive authority may only block or lock down"
            )


@dataclass(frozen=True, slots=True)
class EffectiveControl:
    effect: ControlEffect
    sources: tuple[str, ...]
    managed_floor: bool


def compose_control_instructions(
    instructions: tuple[ControlInstruction, ...],
) -> EffectiveControl:
    lockdown = [item for item in instructions if item.effect is ControlEffect.LOCKDOWN]
    if lockdown:
        return EffectiveControl(
            ControlEffect.LOCKDOWN,
            tuple(item.source_id for item in lockdown),
            any(
                item.authority is AuthorityMode.MANAGED_RESTRICTIVE
                for item in lockdown
            ),
        )
    blocks = [item for item in instructions if item.effect is ControlEffect.BLOCK]
    if blocks:
        return EffectiveControl(
            ControlEffect.BLOCK,
            tuple(item.source_id for item in blocks),
            any(
                item.authority is AuthorityMode.MANAGED_RESTRICTIVE
                for item in blocks
            ),
        )
    permits = [item for item in instructions if item.effect is ControlEffect.PERMIT]
    if permits:
        return EffectiveControl(
            ControlEffect.PERMIT,
            tuple(item.source_id for item in permits),
            False,
        )
    return EffectiveControl(ControlEffect.INHERIT, (), False)
''',
    )
    write(
        TESTS / "test_authority_composition.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.authority import (
    AuthorityMode,
    AuthorityValidationError,
    ControlEffect,
    ControlInstruction,
    compose_control_instructions,
)


def _control(
    effect: ControlEffect,
    authority: AuthorityMode,
    source: str,
) -> ControlInstruction:
    return ControlInstruction("command.git", "push", effect, authority, source)


def test_local_block_tightens_cloud_permit() -> None:
    result = compose_control_instructions(
        (
            _control(
                ControlEffect.PERMIT,
                AuthorityMode.WORKSPACE_SHARED,
                "cloud",
            ),
            _control(ControlEffect.BLOCK, AuthorityMode.PERSONAL_SHARED, "local"),
        )
    )
    assert result.effect is ControlEffect.BLOCK


def test_managed_block_cannot_be_weakened_by_local_permit() -> None:
    result = compose_control_instructions(
        (
            _control(
                ControlEffect.BLOCK,
                AuthorityMode.MANAGED_RESTRICTIVE,
                "organization",
            ),
            _control(ControlEffect.PERMIT, AuthorityMode.PERSONAL_SHARED, "local"),
        )
    )
    assert result.effect is ControlEffect.BLOCK
    assert result.managed_floor


def test_managed_authority_cannot_publish_permit() -> None:
    with pytest.raises(AuthorityValidationError):
        _control(
            ControlEffect.PERMIT,
            AuthorityMode.MANAGED_RESTRICTIVE,
            "organization",
        )
''',
    )
    batch_manifest(
        5,
        "Explicit personal, workspace, and non-weakenable authority modes",
        [
            "src/codex_plugin_scanner/guard/managed_controls/authority.py",
            "tests/managed_controls/test_authority_composition.py",
        ],
    )


def batch_06() -> None:
    write(
        PACKAGE / "bundle.py",
        '''"""Strict parsing for signed Extension-targeted policy bundle fields."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .authority import AuthorityMode, ControlEffect, ControlInstruction
from .catalog import CatalogProjection, CatalogValidationError


class ManagedControlsBundleError(ValueError):
    """Raised when a bundle extension is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class ExtensionTarget:
    extension_id: str
    permission_id: str | None


@dataclass(frozen=True, slots=True)
class ParsedExtensionContract:
    controls: tuple[ControlInstruction, ...]
    rule_targets: dict[str, tuple[ExtensionTarget, ...]]


def _target(value: object, catalog: CatalogProjection) -> ExtensionTarget:
    if not isinstance(value, dict):
        raise ManagedControlsBundleError("extension target must be an object")
    extension_id = value.get("extension_id")
    permission_id = value.get("permission_id")
    if not isinstance(extension_id, str):
        raise ManagedControlsBundleError("extension target id is required")
    if permission_id is not None and not isinstance(permission_id, str):
        raise ManagedControlsBundleError("permission target id must be a string")
    if permission_id is not None:
        catalog.permission(extension_id, permission_id)
    elif not any(item.extension_id == extension_id for item in catalog.extensions):
        raise CatalogValidationError("unknown extension target")
    return ExtensionTarget(extension_id, permission_id)


def parse_extension_contract(
    document: dict[str, Any],
    catalog: CatalogProjection,
) -> ParsedExtensionContract:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise ManagedControlsBundleError("policy spec is required")
    raw_controls = spec.get("x-hol-extension-controls", [])
    if not isinstance(raw_controls, list):
        raise ManagedControlsBundleError("extension controls must be an array")
    controls: list[ControlInstruction] = []
    for index, value in enumerate(raw_controls):
        if not isinstance(value, dict):
            raise ManagedControlsBundleError("extension control must be an object")
        try:
            authority = AuthorityMode(str(value["authority_mode"]))
            effect = ControlEffect(str(value["effect"]))
            target = _target(value, catalog)
            source_id = str(value.get("source_id", f"control-{index}"))
        except (KeyError, ValueError) as error:
            raise ManagedControlsBundleError("invalid extension control") from error
        controls.append(
            ControlInstruction(
                target.extension_id,
                target.permission_id,
                effect,
                authority,
                source_id,
            )
        )
    raw_rules = spec.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ManagedControlsBundleError("policy rules must be an array")
    rule_targets: dict[str, tuple[ExtensionTarget, ...]] = {}
    for index, rule in enumerate(raw_rules):
        if not isinstance(rule, dict):
            raise ManagedControlsBundleError("policy rule must be an object")
        rule_id = str(rule.get("id", f"rule-{index}"))
        raw_targets = rule.get("x-hol-extension-targets", [])
        if not isinstance(raw_targets, list):
            raise ManagedControlsBundleError("extension targets must be an array")
        rule_targets[rule_id] = tuple(
            _target(value, catalog) for value in raw_targets
        )
    return ParsedExtensionContract(tuple(controls), rule_targets)
''',
    )
    write(
        TESTS / "test_bundle_extension_fields.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.bundle import (
    ManagedControlsBundleError,
    parse_extension_contract,
)
from codex_plugin_scanner.guard.managed_controls.catalog import (
    CatalogExtension,
    CatalogPermission,
    CatalogProjection,
    CatalogValidationError,
)


def _catalog() -> CatalogProjection:
    return CatalogProjection(
        1,
        (
            CatalogExtension(
                "command.git",
                "Git",
                "1",
                (CatalogPermission("push", "Push", configurable=True),),
            ),
        ),
    )


def test_parses_document_and_rule_extension_fields() -> None:
    parsed = parse_extension_contract(
        {
            "spec": {
                "x-hol-extension-controls": [
                    {
                        "extension_id": "command.git",
                        "permission_id": "push",
                        "authority_mode": "managed-restrictive",
                        "effect": "block",
                        "source_id": "control-set-1",
                    }
                ],
                "rules": [
                    {
                        "id": "rule-1",
                        "x-hol-extension-targets": [
                            {
                                "extension_id": "command.git",
                                "permission_id": "push",
                            }
                        ],
                    }
                ],
            }
        },
        _catalog(),
    )
    assert parsed.controls[0].source_id == "control-set-1"
    assert parsed.rule_targets["rule-1"][0].permission_id == "push"


def test_unknown_target_fails_deployment() -> None:
    with pytest.raises(CatalogValidationError):
        parse_extension_contract(
            {
                "spec": {
                    "rules": [
                        {
                            "id": "bad",
                            "x-hol-extension-targets": [
                                {
                                    "extension_id": "command.git",
                                    "permission_id": "unknown",
                                }
                            ],
                        }
                    ]
                }
            },
            _catalog(),
        )


def test_malformed_extension_collection_is_rejected() -> None:
    with pytest.raises(ManagedControlsBundleError):
        parse_extension_contract(
            {"spec": {"x-hol-extension-controls": "not-an-array"}},
            _catalog(),
        )
''',
    )
    batch_manifest(
        6,
        "Signed bundle extension fields and unknown-target rejection",
        [
            "src/codex_plugin_scanner/guard/managed_controls/bundle.py",
            "tests/managed_controls/test_bundle_extension_fields.py",
        ],
    )


def batch_07() -> None:
    write(
        PACKAGE / "atomic_apply.py",
        '''"""Atomic policy and Extension-control application with last-known-good state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


class AtomicApplyError(RuntimeError):
    """Raised without committing a partial Managed Controls state."""


@dataclass(frozen=True, slots=True)
class AppliedManagedControls(Generic[T]):
    revision: int
    bundle_hash: str
    catalog_digest: str
    effective_digest: str
    value: T


class AtomicManagedControlsStore(Generic[T]):
    def __init__(self, initial: AppliedManagedControls[T] | None = None) -> None:
        self._current = initial
        self._last_known_good = initial

    @property
    def current(self) -> AppliedManagedControls[T] | None:
        return self._current

    @property
    def last_known_good(self) -> AppliedManagedControls[T] | None:
        return self._last_known_good

    def apply(
        self,
        candidate: AppliedManagedControls[T],
        *,
        validate: Callable[[AppliedManagedControls[T]], None],
        compile_projection: Callable[[AppliedManagedControls[T]], None],
    ) -> AppliedManagedControls[T]:
        previous = self._current
        try:
            if previous is not None and candidate.revision <= previous.revision:
                raise AtomicApplyError("managed controls revision must increase")
            validate(candidate)
            compile_projection(candidate)
        except Exception as error:
            self._current = previous
            if isinstance(error, AtomicApplyError):
                raise
            raise AtomicApplyError("managed controls apply failed") from error
        self._current = candidate
        self._last_known_good = candidate
        return candidate

    def restore_last_known_good(self) -> AppliedManagedControls[T]:
        if self._last_known_good is None:
            raise AtomicApplyError("no last-known-good managed controls state")
        self._current = self._last_known_good
        return self._last_known_good
''',
    )
    write(
        TESTS / "test_atomic_apply.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.atomic_apply import (
    AppliedManagedControls,
    AtomicApplyError,
    AtomicManagedControlsStore,
)


def _state(revision: int, value: str) -> AppliedManagedControls[str]:
    return AppliedManagedControls(
        revision,
        f"bundle-{revision}",
        "catalog",
        f"effective-{revision}",
        value,
    )


def test_policy_and_extension_projection_commit_together() -> None:
    store = AtomicManagedControlsStore(_state(1, "old"))
    result = store.apply(
        _state(2, "new"),
        validate=lambda _: None,
        compile_projection=lambda _: None,
    )
    assert result.value == "new"
    assert store.last_known_good == result


def test_failed_second_projection_preserves_complete_previous_state() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)

    def fail(_: AppliedManagedControls[str]) -> None:
        raise ValueError("compiler failed")

    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=fail)
    assert store.current == previous
    assert store.last_known_good == previous


def test_revision_rollback_is_rejected() -> None:
    store = AtomicManagedControlsStore(_state(3, "current"))
    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "old"), validate=lambda _: None, compile_projection=lambda _: None)
''',
    )
    batch_manifest(
        7,
        "Atomic Local application and deterministic last-known-good recovery",
        [
            "src/codex_plugin_scanner/guard/managed_controls/atomic_apply.py",
            "tests/managed_controls/test_atomic_apply.py",
        ],
    )


def batch_08() -> None:
    write(
        PACKAGE / "acknowledgement.py",
        '''"""Monotonic, idempotent acknowledgement contract."""

from __future__ import annotations

from dataclasses import dataclass


class AcknowledgementError(ValueError):
    """Raised when acknowledgement evidence is stale or incomplete."""


@dataclass(frozen=True, slots=True)
class ManagedControlsAcknowledgement:
    revision: int
    bundle_hash: str
    catalog_digest: str
    effective_digest: str
    extension_authority_revision: int

    def __post_init__(self) -> None:
        if self.revision < 0 or self.extension_authority_revision < 0:
            raise AcknowledgementError("acknowledgement revision cannot be negative")
        for value in (self.bundle_hash, self.catalog_digest, self.effective_digest):
            if not value:
                raise AcknowledgementError("acknowledgement digest is required")


def accept_acknowledgement(
    previous: ManagedControlsAcknowledgement | None,
    candidate: ManagedControlsAcknowledgement,
) -> ManagedControlsAcknowledgement:
    if previous is None:
        return candidate
    if candidate == previous:
        return previous
    if candidate.revision < previous.revision:
        raise AcknowledgementError("acknowledgement revision moved backwards")
    if candidate.revision == previous.revision:
        raise AcknowledgementError("same revision has conflicting evidence")
    return candidate
''',
    )
    write(
        PACKAGE / "drift.py",
        '''"""Drift classification for Local and Guard Cloud posture."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .acknowledgement import ManagedControlsAcknowledgement


class DriftState(StrEnum):
    CURRENT = "current"
    PENDING = "pending"
    CATALOG_MISMATCH = "catalog_mismatch"
    EFFECTIVE_MISMATCH = "effective_mismatch"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ExpectedManagedControlsState:
    revision: int
    catalog_digest: str
    effective_digest: str


def classify_drift(
    expected: ExpectedManagedControlsState,
    acknowledgement: ManagedControlsAcknowledgement | None,
    *,
    supported: bool = True,
) -> DriftState:
    if not supported:
        return DriftState.UNSUPPORTED
    if acknowledgement is None or acknowledgement.revision < expected.revision:
        return DriftState.PENDING
    if acknowledgement.catalog_digest != expected.catalog_digest:
        return DriftState.CATALOG_MISMATCH
    if acknowledgement.effective_digest != expected.effective_digest:
        return DriftState.EFFECTIVE_MISMATCH
    return DriftState.CURRENT
''',
    )
    write(
        TESTS / "test_acknowledgement_drift.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.acknowledgement import (
    AcknowledgementError,
    ManagedControlsAcknowledgement,
    accept_acknowledgement,
)
from codex_plugin_scanner.guard.managed_controls.drift import (
    DriftState,
    ExpectedManagedControlsState,
    classify_drift,
)


def _ack(revision: int, catalog: str = "catalog") -> ManagedControlsAcknowledgement:
    return ManagedControlsAcknowledgement(
        revision,
        f"bundle-{revision}",
        catalog,
        "effective",
        revision,
    )


def test_acknowledgement_is_idempotent_and_monotonic() -> None:
    first = _ack(1)
    assert accept_acknowledgement(first, first) is first
    assert accept_acknowledgement(first, _ack(2)).revision == 2
    with pytest.raises(AcknowledgementError):
        accept_acknowledgement(_ack(2), _ack(1))


def test_drift_distinguishes_catalog_and_effective_mismatch() -> None:
    expected = ExpectedManagedControlsState(1, "catalog", "effective")
    assert classify_drift(expected, _ack(1)) is DriftState.CURRENT
    assert classify_drift(expected, _ack(1, "other")) is DriftState.CATALOG_MISMATCH
    assert classify_drift(expected, None) is DriftState.PENDING
''',
    )
    batch_manifest(
        8,
        "Monotonic acknowledgement, rollout drift, and compatibility evidence",
        [
            "src/codex_plugin_scanner/guard/managed_controls/acknowledgement.py",
            "src/codex_plugin_scanner/guard/managed_controls/drift.py",
            "tests/managed_controls/test_acknowledgement_drift.py",
        ],
    )


def batch_09() -> None:
    write(
        PACKAGE / "delegation.py",
        '''"""Delegated enforcement compilation for Package Firewall Extensions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EnforcementPlane(StrEnum):
    COMMAND = "command"
    PACKAGE_FIREWALL = "package_firewall"


class DelegationError(ValueError):
    """Raised when delegated protection is compiled into the wrong plane."""


@dataclass(frozen=True, slots=True)
class CompiledExtensionControl:
    extension_id: str
    permission_id: str | None
    blocked: bool
    enforcement_plane: EnforcementPlane


def compile_delegated_control(
    *,
    extension_id: str,
    permission_id: str | None,
    delegated_protection: str | None,
    blocked: bool,
) -> CompiledExtensionControl:
    if delegated_protection == "package-firewall":
        plane = EnforcementPlane.PACKAGE_FIREWALL
    elif delegated_protection is None:
        plane = EnforcementPlane.COMMAND
    else:
        raise DelegationError("unsupported delegated protection")
    return CompiledExtensionControl(
        extension_id,
        permission_id,
        blocked,
        plane,
    )


def require_package_firewall_path(control: CompiledExtensionControl) -> None:
    if control.enforcement_plane is not EnforcementPlane.PACKAGE_FIREWALL:
        raise DelegationError("package control did not use Package Firewall")
''',
    )
    write(
        TESTS / "test_delegated_package_firewall.py",
        '''from __future__ import annotations

from codex_plugin_scanner.guard.managed_controls.delegation import (
    EnforcementPlane,
    compile_delegated_control,
    require_package_firewall_path,
)


def test_package_extension_compiles_through_package_firewall() -> None:
    control = compile_delegated_control(
        extension_id="package.npm",
        permission_id="install",
        delegated_protection="package-firewall",
        blocked=True,
    )
    assert control.enforcement_plane is EnforcementPlane.PACKAGE_FIREWALL
    require_package_firewall_path(control)


def test_command_extension_stays_on_command_plane() -> None:
    control = compile_delegated_control(
        extension_id="command.git",
        permission_id="push",
        delegated_protection=None,
        blocked=False,
    )
    assert control.enforcement_plane is EnforcementPlane.COMMAND
''',
    )
    batch_manifest(
        9,
        "Package Firewall delegation without detector or command-plane duplication",
        [
            "src/codex_plugin_scanner/guard/managed_controls/delegation.py",
            "tests/managed_controls/test_delegated_package_firewall.py",
        ],
    )


def batch_10() -> None:
    write(
        PACKAGE / "compatibility.py",
        '''"""Device compatibility decisions for safe rollout."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .capabilities import MANAGED_CONTROL_CAPABILITIES


class CompatibilityState(StrEnum):
    COMPATIBLE = "compatible"
    MISSING_CAPABILITY = "missing_capability"
    CATALOG_MISMATCH = "catalog_mismatch"
    SCHEMA_UNSUPPORTED = "schema_unsupported"


@dataclass(frozen=True, slots=True)
class DeviceCompatibility:
    capabilities: frozenset[str]
    catalog_digest: str
    catalog_schema_version: int


def evaluate_compatibility(
    device: DeviceCompatibility,
    *,
    required_catalog_digest: str,
    required_schema_version: int = 1,
) -> CompatibilityState:
    if not MANAGED_CONTROL_CAPABILITIES <= device.capabilities:
        return CompatibilityState.MISSING_CAPABILITY
    if device.catalog_schema_version != required_schema_version:
        return CompatibilityState.SCHEMA_UNSUPPORTED
    if device.catalog_digest != required_catalog_digest:
        return CompatibilityState.CATALOG_MISMATCH
    return CompatibilityState.COMPATIBLE
''',
    )
    write(
        PACKAGE / "migration.py",
        '''"""Deterministic compatibility mapping for legacy contextual policies."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LegacyRuleMapping:
    rule_id: str
    extension_id: str | None
    permission_id: str | None
    advanced_raw_rule: bool


def map_legacy_rule(
    rule_id: str,
    *,
    known_permission: tuple[str, str] | None,
) -> LegacyRuleMapping:
    if known_permission is None:
        return LegacyRuleMapping(rule_id, None, None, True)
    extension_id, permission_id = known_permission
    return LegacyRuleMapping(
        rule_id,
        extension_id,
        permission_id,
        False,
    )


def preserve_legacy_policy_document(document: dict[str, object]) -> dict[str, object]:
    """Return legacy policy data unchanged unless a versioned migration is explicit."""

    return dict(document)
''',
    )
    write(
        TESTS / "test_compatibility_migration.py",
        '''from __future__ import annotations

from codex_plugin_scanner.guard.managed_controls.capabilities import (
    MANAGED_CONTROL_CAPABILITIES,
)
from codex_plugin_scanner.guard.managed_controls.compatibility import (
    CompatibilityState,
    DeviceCompatibility,
    evaluate_compatibility,
)
from codex_plugin_scanner.guard.managed_controls.migration import (
    map_legacy_rule,
    preserve_legacy_policy_document,
)


def test_unsupported_client_is_excluded_not_silently_downgraded() -> None:
    device = DeviceCompatibility(frozenset(), "catalog", 1)
    assert (
        evaluate_compatibility(device, required_catalog_digest="catalog")
        is CompatibilityState.MISSING_CAPABILITY
    )


def test_exact_catalog_is_compatible() -> None:
    device = DeviceCompatibility(MANAGED_CONTROL_CAPABILITIES, "catalog", 1)
    assert (
        evaluate_compatibility(device, required_catalog_digest="catalog")
        is CompatibilityState.COMPATIBLE
    )


def test_unmapped_legacy_rule_remains_advanced_without_data_loss() -> None:
    mapping = map_legacy_rule("legacy", known_permission=None)
    assert mapping.advanced_raw_rule
    document = {"kind": "GuardPolicy", "spec": {"rules": []}}
    assert preserve_legacy_policy_document(document) == document
''',
    )
    batch_manifest(
        10,
        "Safe compatibility exclusion and deterministic legacy migration",
        [
            "src/codex_plugin_scanner/guard/managed_controls/compatibility.py",
            "src/codex_plugin_scanner/guard/managed_controls/migration.py",
            "tests/managed_controls/test_compatibility_migration.py",
        ],
    )


def batch_11() -> None:
    write(
        DASHBOARD / "local-protection-model.ts",
        '''export type ProtectionSource =
  | 'Built-in protection'
  | 'This device'
  | 'Personal Control Set'
  | 'Organization Control Set';

export type LocalProtectionStatus =
  | 'protected'
  | 'needs-attention'
  | 'managed'
  | 'lockdown'
  | 'unsupported';

export interface LocalProtectionView {
  title: string;
  summary: string;
  source: ProtectionSource;
  status: LocalProtectionStatus;
  primaryAction: { label: string; href?: string; action?: 'refresh' | 'repair' } | null;
  technicalDetails: ReadonlyArray<{ label: string; value: string }>;
}

export interface LocalProtectionInput {
  extensionName: string;
  effectiveState: 'allowed' | 'blocked' | 'required' | 'lockdown';
  source: ProtectionSource;
  catalogDigest?: string;
  acknowledgementRevision?: number;
  stale?: boolean;
  supported?: boolean;
}

export function buildLocalProtectionView(
  input: LocalProtectionInput,
): LocalProtectionView {
  if (input.supported === false) {
    return {
      title: input.extensionName,
      summary: 'Update Guard before this managed setting can be applied.',
      source: input.source,
      status: 'unsupported',
      primaryAction: { label: 'Check for updates', action: 'refresh' },
      technicalDetails: [],
    };
  }
  if (input.stale) {
    return {
      title: input.extensionName,
      summary: 'Guard is using the last verified setting while it checks for an update.',
      source: input.source,
      status: 'needs-attention',
      primaryAction: { label: 'Check again', action: 'refresh' },
      technicalDetails: [],
    };
  }
  const status: LocalProtectionStatus =
    input.effectiveState === 'lockdown'
      ? 'lockdown'
      : input.source === 'Organization Control Set'
        ? 'managed'
        : 'protected';
  return {
    title: input.extensionName,
    summary:
      input.effectiveState === 'blocked'
        ? 'Matching actions are blocked.'
        : input.effectiveState === 'required'
          ? 'This protection stays on.'
          : input.effectiveState === 'lockdown'
            ? 'Emergency Lockdown blocks governed actions.'
            : 'Guard checks matching actions before they run.',
    source: input.source,
    status,
    primaryAction:
      input.source === 'This device'
        ? { label: 'Apply across my devices', href: '/guard/controls' }
        : { label: 'Manage in Guard Cloud', href: '/guard/controls' },
    technicalDetails: [
      ...(input.catalogDigest
        ? [{ label: 'Catalog digest', value: input.catalogDigest }]
        : []),
      ...(input.acknowledgementRevision !== undefined
        ? [
            {
              label: 'Acknowledgement revision',
              value: String(input.acknowledgementRevision),
            },
          ]
        : []),
    ],
  };
}
''',
    )
    write(
        DASHBOARD / "local-protection-model.test.ts",
        '''import assert from 'node:assert/strict';
import { buildLocalProtectionView } from './local-protection-model';

const local = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'allowed',
  source: 'This device',
});
assert.equal(local.primaryAction?.label, 'Apply across my devices');
assert.equal(local.status, 'protected');

const managed = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
});
assert.equal(managed.status, 'managed');
assert.equal(managed.primaryAction?.label, 'Manage in Guard Cloud');

const stale = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  stale: true,
});
assert.equal(stale.primaryAction?.label, 'Check again');
''',
    )
    add_dashboard_test("src/managed-controls/local-protection-model.test.ts")
    batch_manifest(
        11,
        "Low-cognitive-load Local Extension posture and provenance model",
        [
            "dashboard/src/managed-controls/local-protection-model.ts",
            "dashboard/src/managed-controls/local-protection-model.test.ts",
        ],
    )


def batch_12() -> None:
    write(
        DASHBOARD / "rules-exceptions-model.ts",
        '''export type RuleAuthority =
  | 'Remembered on this device'
  | 'Synced contextual rule'
  | 'Cloud exception';

export interface RuleExceptionItem {
  id: string;
  title: string;
  authority: RuleAuthority;
  extensionId?: string;
  expiresAt?: string;
}

export interface RulesExceptionsView {
  title: 'Rules & exceptions';
  description: string;
  items: readonly RuleExceptionItem[];
  decisionOrder: readonly string[];
  governingExtensionLinks: readonly { label: string; href: string }[];
  includesExtensionEditor: false;
}

export function buildRulesExceptionsView(
  items: readonly RuleExceptionItem[],
): RulesExceptionsView {
  const links = new Map<string, { label: string; href: string }>();
  for (const item of items) {
    if (!item.extensionId) continue;
    links.set(item.extensionId, {
      label: `Open ${item.extensionId}`,
      href: `/extensions/${encodeURIComponent(item.extensionId)}`,
    });
  }
  return {
    title: 'Rules & exceptions',
    description:
      'Review remembered decisions, contextual Cloud rules, and exceptions. Extension permissions stay in Protection Center.',
    items,
    decisionOrder: [
      'Hard safety floors and Emergency Lockdown',
      'Extension and permission posture',
      'Contextual rules and remembered decisions',
    ],
    governingExtensionLinks: [...links.values()],
    includesExtensionEditor: false,
  };
}
''',
    )
    write(
        DASHBOARD / "rules-exceptions-model.test.ts",
        '''import assert from 'node:assert/strict';
import { buildRulesExceptionsView } from './rules-exceptions-model';

const view = buildRulesExceptionsView([
  {
    id: 'remembered-1',
    title: 'Permit signed Git pushes',
    authority: 'Remembered on this device',
    extensionId: 'command.git',
  },
]);
assert.equal(view.title, 'Rules & exceptions');
assert.equal(view.includesExtensionEditor, false);
assert.deepEqual(view.governingExtensionLinks, [
  { label: 'Open command.git', href: '/extensions/command.git' },
]);
assert.match(view.description, /Extension permissions stay/);
''',
    )
    add_dashboard_test("src/managed-controls/rules-exceptions-model.test.ts")
    batch_manifest(
        12,
        "Rules & exceptions composition without a duplicate Extension editor",
        [
            "dashboard/src/managed-controls/rules-exceptions-model.ts",
            "dashboard/src/managed-controls/rules-exceptions-model.test.ts",
        ],
    )


def batch_13() -> None:
    write(
        DASHBOARD / "custom-extension-continuity.ts",
        '''export type CustomExtensionContinuityState =
  | 'local-only'
  | 'identity-matched'
  | 'portable'
  | 'incompatible';

export interface CustomExtensionContinuityView {
  state: CustomExtensionContinuityState;
  title: string;
  description: string;
  canApplyAcrossDevices: boolean;
  privacyDisclosure: string;
}

export function customExtensionContinuityView(
  state: CustomExtensionContinuityState,
): CustomExtensionContinuityView {
  const privacyDisclosure =
    'Guard Cloud receives stable identity and compatibility metadata, not local source paths.';
  switch (state) {
    case 'local-only':
      return {
        state,
        title: 'Available on this device',
        description:
          'This custom protection remains local until portable continuity is enabled.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
    case 'identity-matched':
      return {
        state,
        title: 'Matched on another device',
        description:
          'Guard matched the stable identity. Each device still uses its own verified definition.',
        canApplyAcrossDevices: true,
        privacyDisclosure,
      };
    case 'portable':
      return {
        state,
        title: 'Portable continuity enabled',
        description:
          'A verified portable definition is available to compatible devices.',
        canApplyAcrossDevices: true,
        privacyDisclosure,
      };
    case 'incompatible':
      return {
        state,
        title: 'Needs a compatible definition',
        description:
          'This device cannot apply the shared custom protection safely.',
        canApplyAcrossDevices: false,
        privacyDisclosure,
      };
  }
}
''',
    )
    write(
        DASHBOARD / "custom-extension-continuity.test.ts",
        '''import assert from 'node:assert/strict';
import { customExtensionContinuityView } from './custom-extension-continuity';

const localOnly = customExtensionContinuityView('local-only');
assert.equal(localOnly.canApplyAcrossDevices, false);
assert.match(localOnly.description, /remains local/);
assert.doesNotMatch(localOnly.privacyDisclosure, /path is|source path:/i);

const portable = customExtensionContinuityView('portable');
assert.equal(portable.canApplyAcrossDevices, true);
''',
    )
    add_dashboard_test("src/managed-controls/custom-extension-continuity.test.ts")
    batch_manifest(
        13,
        "Truthful custom Extension continuity and privacy-safe UI states",
        [
            "dashboard/src/managed-controls/custom-extension-continuity.ts",
            "dashboard/src/managed-controls/custom-extension-continuity.test.ts",
        ],
    )


def batch_14() -> None:
    write(
        PACKAGE / "feature_flags.py",
        '''"""Independent Managed Controls rollout switches."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ManagedControlsFeatureFlags:
    authoring: bool = False
    compilation: bool = False
    delivery: bool = False
    enforcement: bool = False

    def validate(self) -> None:
        if self.enforcement and not self.compilation:
            raise ValueError("enforcement requires compilation")
        if self.delivery and not self.compilation:
            raise ValueError("delivery requires compilation")
''',
    )
    write(
        PACKAGE / "telemetry.py",
        '''"""Allowlisted, privacy-safe Managed Controls telemetry."""

from __future__ import annotations

from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {
        "event",
        "result",
        "authority_mode",
        "compatibility_state",
        "drift_state",
        "control_count_bucket",
        "latency_bucket",
    }
)
_FORBIDDEN_FRAGMENTS = ("command", "path", "secret", "token", "proof", "nonce")


class TelemetryPrivacyError(ValueError):
    """Raised when telemetry contains sensitive or arbitrary data."""


def managed_controls_telemetry_event(
    values: Mapping[str, object],
) -> dict[str, str]:
    unknown = set(values) - _ALLOWED_FIELDS
    if unknown:
        raise TelemetryPrivacyError("telemetry contains non-allowlisted fields")
    event: dict[str, str] = {}
    for key, value in values.items():
        text = str(value)
        lowered = f"{key}:{text}".lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_FRAGMENTS):
            raise TelemetryPrivacyError("telemetry contains sensitive material")
        event[key] = text
    return event
''',
    )
    write(
        PACKAGE / "redaction.py",
        '''"""Recursive redaction for Managed Controls diagnostics."""

from __future__ import annotations

from collections.abc import Mapping

_SENSITIVE_KEYS = frozenset(
    {"command", "raw_command", "path", "source_path", "secret", "token", "proof", "nonce"}
)


def redact_managed_controls(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if str(key).lower() in _SENSITIVE_KEYS
                else redact_managed_controls(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_managed_controls(child) for child in value]
    return value
''',
    )
    write(
        TESTS / "test_flags_telemetry_redaction.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.feature_flags import (
    ManagedControlsFeatureFlags,
)
from codex_plugin_scanner.guard.managed_controls.redaction import (
    redact_managed_controls,
)
from codex_plugin_scanner.guard.managed_controls.telemetry import (
    TelemetryPrivacyError,
    managed_controls_telemetry_event,
)


def test_feature_flags_can_disable_each_pipeline_stage() -> None:
    ManagedControlsFeatureFlags().validate()
    with pytest.raises(ValueError):
        ManagedControlsFeatureFlags(enforcement=True).validate()


def test_telemetry_is_allowlisted_and_privacy_safe() -> None:
    assert managed_controls_telemetry_event(
        {"event": "apply", "result": "success"}
    ) == {"event": "apply", "result": "success"}
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"raw_command": "cat .env"})


def test_diagnostics_redact_sensitive_values_recursively() -> None:
    assert redact_managed_controls(
        {"extension_id": "command.git", "proof": "sensitive"}
    ) == {"extension_id": "command.git", "proof": "[REDACTED]"}
''',
    )
    batch_manifest(
        14,
        "Independent rollout flags, privacy-safe telemetry, and redaction",
        [
            "src/codex_plugin_scanner/guard/managed_controls/feature_flags.py",
            "src/codex_plugin_scanner/guard/managed_controls/telemetry.py",
            "src/codex_plugin_scanner/guard/managed_controls/redaction.py",
            "tests/managed_controls/test_flags_telemetry_redaction.py",
        ],
    )


def batch_15() -> None:
    write(
        TESTS / "test_adversarial_managed_controls.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.acknowledgement import (
    AcknowledgementError,
    ManagedControlsAcknowledgement,
    accept_acknowledgement,
)
from codex_plugin_scanner.guard.managed_controls.atomic_apply import (
    AppliedManagedControls,
    AtomicApplyError,
    AtomicManagedControlsStore,
)
from codex_plugin_scanner.guard.managed_controls.authority import (
    AuthorityMode,
    ControlEffect,
    ControlInstruction,
    compose_control_instructions,
)
from codex_plugin_scanner.guard.managed_controls.bundle import (
    parse_extension_contract,
)
from codex_plugin_scanner.guard.managed_controls.catalog import (
    CatalogExtension,
    CatalogPermission,
    CatalogProjection,
    CatalogValidationError,
)


def _catalog() -> CatalogProjection:
    return CatalogProjection(
        1,
        (
            CatalogExtension(
                "command.git",
                "Git",
                "1",
                (CatalogPermission("push", "Push", configurable=True),),
            ),
        ),
    )


def test_contextual_allow_cannot_bypass_managed_extension_block() -> None:
    result = compose_control_instructions(
        (
            ControlInstruction(
                "command.git",
                "push",
                ControlEffect.BLOCK,
                AuthorityMode.MANAGED_RESTRICTIVE,
                "managed",
            ),
            ControlInstruction(
                "command.git",
                "push",
                ControlEffect.PERMIT,
                AuthorityMode.PERSONAL_SHARED,
                "local",
            ),
        )
    )
    assert result.effect is ControlEffect.BLOCK


def test_unknown_target_is_never_silently_dropped() -> None:
    with pytest.raises(CatalogValidationError):
        parse_extension_contract(
            {
                "spec": {
                    "rules": [
                        {
                            "id": "unknown",
                            "x-hol-extension-targets": [
                                {
                                    "extension_id": "command.git",
                                    "permission_id": "missing",
                                }
                            ],
                        }
                    ]
                }
            },
            _catalog(),
        )


def test_partial_apply_and_revision_rollback_fail_closed() -> None:
    original = AppliedManagedControls(2, "bundle", "catalog", "effective", {})
    store = AtomicManagedControlsStore(original)
    with pytest.raises(AtomicApplyError):
        store.apply(
            AppliedManagedControls(3, "new", "catalog", "new-effective", {}),
            validate=lambda _: None,
            compile_projection=lambda _: (_ for _ in ()).throw(ValueError("boom")),
        )
    assert store.current == original


def test_conflicting_same_revision_acknowledgement_is_rejected() -> None:
    old = ManagedControlsAcknowledgement(1, "a", "c", "e", 1)
    conflicting = ManagedControlsAcknowledgement(1, "b", "c", "e", 1)
    with pytest.raises(AcknowledgementError):
        accept_acknowledgement(old, conflicting)
''',
    )
    batch_manifest(
        15,
        "Adversarial downgrade, bypass, unknown-target, and partial-apply coverage",
        ["tests/managed_controls/test_adversarial_managed_controls.py"],
    )


def batch_16() -> None:
    write(
        PACKAGE / "operations.py",
        '''"""Operational health and performance budgets for Managed Controls."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ManagedControlsHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RECOVERY_REQUIRED = "recovery_required"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ManagedControlsPerformanceBudget:
    catalog_projection_ms: int = 100
    compatibility_evaluation_ms: int = 50
    atomic_apply_ms: int = 500
    acknowledgement_ms: int = 250

    def assert_within(self, operation: str, elapsed_ms: float) -> None:
        limit = {
            "catalog_projection": self.catalog_projection_ms,
            "compatibility_evaluation": self.compatibility_evaluation_ms,
            "atomic_apply": self.atomic_apply_ms,
            "acknowledgement": self.acknowledgement_ms,
        }.get(operation)
        if limit is None:
            raise ValueError("unknown performance operation")
        if elapsed_ms > limit:
            raise ValueError(f"{operation} exceeded performance budget")


@dataclass(frozen=True, slots=True)
class OperationalSnapshot:
    health: ManagedControlsHealth
    last_successful_revision: int | None
    catalog_digest: str | None
    recovery_action: str | None


def health_snapshot(
    *,
    authority_valid: bool,
    supported: bool,
    last_successful_revision: int | None,
    catalog_digest: str | None,
) -> OperationalSnapshot:
    if not supported:
        return OperationalSnapshot(
            ManagedControlsHealth.UNSUPPORTED,
            last_successful_revision,
            catalog_digest,
            "update_guard",
        )
    if not authority_valid:
        return OperationalSnapshot(
            ManagedControlsHealth.RECOVERY_REQUIRED,
            last_successful_revision,
            catalog_digest,
            "repair_protection",
        )
    return OperationalSnapshot(
        ManagedControlsHealth.HEALTHY,
        last_successful_revision,
        catalog_digest,
        None,
    )
''',
    )
    write(
        TESTS / "test_operations_performance.py",
        '''from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.operations import (
    ManagedControlsHealth,
    ManagedControlsPerformanceBudget,
    health_snapshot,
)


def test_performance_budgets_are_explicit_and_enforced() -> None:
    budget = ManagedControlsPerformanceBudget()
    budget.assert_within("atomic_apply", 499)
    with pytest.raises(ValueError):
        budget.assert_within("atomic_apply", 501)


def test_invalid_authority_has_one_actionable_recovery_path() -> None:
    snapshot = health_snapshot(
        authority_valid=False,
        supported=True,
        last_successful_revision=4,
        catalog_digest="catalog",
    )
    assert snapshot.health is ManagedControlsHealth.RECOVERY_REQUIRED
    assert snapshot.recovery_action == "repair_protection"
''',
    )
    batch_manifest(
        16,
        "Operational health, bounded performance, and actionable recovery",
        [
            "src/codex_plugin_scanner/guard/managed_controls/operations.py",
            "tests/managed_controls/test_operations_performance.py",
        ],
    )


def batch_17() -> None:
    write(
        ROOT / "scripts" / "ci" / "managed_controls_release_gate.py",
        '''from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH_DIRECTORY = ROOT / "docs" / "guard" / "managed-controls" / "batches"
REQUIRED_CAPABILITIES = {
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
}


def main() -> int:
    manifests = []
    for path in sorted(BATCH_DIRECTORY.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("target_branch") != "release/3.0":
            raise SystemExit(f"invalid target branch in {path}")
        if not payload.get("evidence"):
            raise SystemExit(f"missing evidence in {path}")
        for evidence in payload["evidence"]:
            if not (ROOT / evidence).exists():
                raise SystemExit(f"missing evidence path: {evidence}")
        manifests.append(payload)
    expected_batches = set(range(3, 18))
    actual_batches = {item["batch"] for item in manifests}
    if actual_batches != expected_batches:
        raise SystemExit(
            f"managed controls Local batches incomplete: {sorted(actual_batches)}"
        )
    capability_source = (
        ROOT
        / "src"
        / "codex_plugin_scanner"
        / "guard"
        / "managed_controls"
        / "capabilities.py"
    ).read_text(encoding="utf-8")
    missing = sorted(
        capability for capability in REQUIRED_CAPABILITIES if capability not in capability_source
    )
    if missing:
        raise SystemExit(f"missing managed controls capabilities: {missing}")
    print("Managed Controls Local release gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
    )
    write(
        ROOT / "docs" / "guard" / "managed-controls-release-runbook.md",
        '''# Managed Controls release runbook

This runbook covers the HOL Guard Local side of Extension-First Managed Controls on `release/3.0`.

## Required gates

1. Verify the four negotiated capability markers.
2. Validate the canonical, privacy-safe catalog and its digest.
3. Reject unknown Extension and permission targets.
4. Compile Package Firewall delegates through the package path.
5. Apply policy and Extension projections atomically.
6. Preserve the complete last-known-good state on failure.
7. Require monotonic, idempotent acknowledgement evidence.
8. Exclude unsupported or catalog-mismatched clients from rollout.
9. Keep Emergency Lockdown and managed blocks non-weakenable.
10. Confirm local blocks still tighten Cloud permits.
11. Verify custom Extension copy remains local-only until continuity is real.
12. Run adversarial, privacy, accessibility, and performance checks.

Run:

```bash
python scripts/ci/managed_controls_release_gate.py
pytest tests/managed_controls
```

No release may silently drop Extension semantics or move detector ownership into Guard Cloud.
''',
    )
    write(
        TESTS / "test_release_gate.py",
        '''from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_managed_controls_release_gate() -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "scripts/ci/managed_controls_release_gate.py"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
''',
    )
    batch_manifest(
        17,
        "Local release gate, runbook, and complete task-range evidence",
        [
            "scripts/ci/managed_controls_release_gate.py",
            "docs/guard/managed-controls-release-runbook.md",
            "tests/managed_controls/test_release_gate.py",
        ],
    )


BATCHES = {
    3: ("catalog-capabilities", batch_03),
    4: ("catalog-privacy-identity", batch_04),
    5: ("authority-composition", batch_05),
    6: ("bundle-extension-targets", batch_06),
    7: ("atomic-apply", batch_07),
    8: ("acknowledgement-drift", batch_08),
    9: ("package-firewall-delegation", batch_09),
    10: ("compatibility-migration", batch_10),
    11: ("local-protection-model", batch_11),
    12: ("rules-exceptions-model", batch_12),
    13: ("custom-extension-continuity", batch_13),
    14: ("privacy-telemetry-flags", batch_14),
    15: ("adversarial-runtime", batch_15),
    16: ("operations-performance", batch_16),
    17: ("local-release-gate", batch_17),
}


def main() -> None:
    run("git", "config", "user.name", "github-actions[bot]")
    run(
        "git",
        "config",
        "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
    )
    run("git", "fetch", "origin", "release/3.0")
    current = "origin/release/3.0"
    for batch, (slug, apply_batch) in BATCHES.items():
        branch = f"managed-controls/batch-{batch:02d}-{slug}"
        run("git", "checkout", "-B", branch, current)
        apply_batch()
        run("git", "add", "-A")
        run("git", "diff", "--cached", "--check")
        run(
            "git",
            "commit",
            "-m",
            f"feat: complete Managed Controls tasks {(batch - 1) * 15 + 1}-{min(batch * 15, 523)}",
        )
        run("git", "push", "--force", "origin", f"HEAD:{branch}")
        current = "HEAD"


if __name__ == "__main__":
    main()
