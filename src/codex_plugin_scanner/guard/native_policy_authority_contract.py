"""Bounded values for the versioned scoped native authority contract.

These values are compilation output, not application evidence. They require
an authenticated V4 snapshot and a consumer advertising the exact capability.
The existing V3 publisher deliberately does not emit this contract.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from .native_managed_configuration import MANAGED_CONFIGURATION_FEATURE, NativeManagedConfiguration
from .native_policy_authority_expressions import NATIVE_COMMAND_EXPRESSIONS_FEATURE, NativeScopedCommandExpression
from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,  # pyright: ignore[reportPrivateUsage]
    _digest_v3,  # pyright: ignore[reportPrivateUsage]
)
from .native_policy_snapshot_constants import NativePolicySnapshotError

NATIVE_POLICY_AUTHORITY_SCHEMA: Final = "guard-native-policy-authority.v1"
NATIVE_SCOPED_AUTHORITY_FEATURE: Final = "policy-scoped-authority-v1"
NATIVE_MANAGED_AUTHORITY_FEATURE: Final = "policy-managed-authority-v1"
NATIVE_AUTHORITY_MAX_ROWS: Final = 256
NATIVE_AUTHORITY_MAX_BYTES: Final = 192 * 1024
NATIVE_AUTHORITY_MAX_CONTROLS: Final = 512
_MAX_TEXT_BYTES: Final = 4096
_MAX_EXACT_INTEGER: Final = (1 << 53) - 1
_EXACT_CONTEXT_FAMILIES: Final = frozenset({"file-read", "mcp-tool", "package-request", "prompt", "tool-action"})
_CONTROL_TARGET = re.compile(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*")


class NativePolicyScope(str, Enum):
    ARTIFACT = "artifact"
    WORKSPACE = "workspace"
    PUBLISHER = "publisher"
    HARNESS = "harness"
    GLOBAL = "global"


class NativePolicyAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    REVIEW = "review"
    REQUIRE_REAPPROVAL = "require-reapproval"
    SANDBOX_REQUIRED = "sandbox-required"
    BLOCK = "block"


class NativePolicySourceKind(str, Enum):
    LOCAL = "local"
    SIGNED_BUNDLE = "signed-bundle"
    SIGNED_MEMORY = "signed-memory"


def bounded_authority_text(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise NativePolicySnapshotError("native_policy_authority_text_invalid")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise NativePolicySnapshotError("native_policy_authority_text_invalid") from error
    if size > _MAX_TEXT_BYTES:
        raise NativePolicySnapshotError("native_policy_authority_text_invalid")
    return value


def authority_integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= _MAX_EXACT_INTEGER:
        raise NativePolicySnapshotError("native_policy_authority_integer_invalid")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class NativePolicyAuthorityCapabilities:
    snapshot_version: int
    features: frozenset[str]
    catalog_digest: str | None = None

    def __post_init__(self) -> None:
        _ = authority_integer(self.snapshot_version, positive=True)
        if type(self.features) is not frozenset or len(self.features) > 256:
            raise NativePolicySnapshotError("native_policy_authority_capability_invalid")
        for feature in self.features:
            _ = bounded_authority_text(feature)
        _ = bounded_authority_text(self.catalog_digest, optional=True)

    def require(self, *, managed: bool, command_expressions: bool = False, managed_config: bool = False) -> None:
        required = {NATIVE_SCOPED_AUTHORITY_FEATURE}
        if managed:
            required.add(NATIVE_MANAGED_AUTHORITY_FEATURE)
        if command_expressions:
            required.add(NATIVE_COMMAND_EXPRESSIONS_FEATURE)
        if managed_config:
            required.add(MANAGED_CONFIGURATION_FEATURE)
        if self.snapshot_version != 4 or not required.issubset(self.features):
            raise NativePolicySnapshotError("native_policy_authority_capability_unsupported")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> NativePolicyAuthorityCapabilities:
        raw_features = value.get("features")
        if not isinstance(raw_features, list):
            raise NativePolicySnapshotError("native_policy_authority_capability_invalid")
        feature_values = cast(list[object], raw_features)
        if len(feature_values) > 256:
            raise NativePolicySnapshotError("native_policy_authority_capability_invalid")
        features = frozenset(cast(str, bounded_authority_text(item)) for item in feature_values)
        snapshot_version = authority_integer(value.get("policy_snapshot_version"), positive=True)
        catalog_digest = bounded_authority_text(value.get("extension_catalog_digest"), optional=True)
        return cls(snapshot_version, features, catalog_digest)


@dataclass(frozen=True, slots=True, repr=False)
class NativeScopedPolicyRow:
    decision_id: int
    harness: str
    scope: NativePolicyScope
    action: NativePolicyAction
    source_kind: NativePolicySourceKind
    updated_at_us: int
    artifact_id: str | None = None
    artifact_hash: str | None = None
    workspace: str | None = None
    publisher: str | None = None
    expires_at_ms: int | None = None
    exact_command_sha256: str | None = None

    def __post_init__(self) -> None:
        _ = authority_integer(self.decision_id, positive=True)
        _ = authority_integer(self.updated_at_us)
        if self.expires_at_ms is not None:
            _ = authority_integer(self.expires_at_ms)
        _ = bounded_authority_text(self.harness)
        for selector in (self.artifact_id, self.artifact_hash, self.workspace, self.publisher):
            _ = bounded_authority_text(selector, optional=True)
        if self.exact_command_sha256 is not None and (
            not isinstance(self.exact_command_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.exact_command_sha256) is None
            or self.artifact_id is None
            or self.scope not in {NativePolicyScope.ARTIFACT, NativePolicyScope.WORKSPACE}
        ):
            raise NativePolicySnapshotError("native_policy_authority_exact_command_invalid")
        for value, enum_type in (
            (self.scope, NativePolicyScope),
            (self.action, NativePolicyAction),
            (self.source_kind, NativePolicySourceKind),
        ):
            if type(value) is not enum_type:
                raise NativePolicySnapshotError("native_policy_authority_enum_invalid")
        self._validate_scope()

    def _validate_scope(self) -> None:
        if self.scope is NativePolicyScope.ARTIFACT:
            valid = self.artifact_id is not None and self.workspace is None and self.publisher is None
        elif self.scope is NativePolicyScope.WORKSPACE:
            valid = self.workspace is not None and self.publisher is None
        elif self.scope is NativePolicyScope.PUBLISHER:
            valid = self.publisher is not None and self.workspace is None and self.artifact_id is None
        else:
            valid = (
                self.workspace is None
                and self.publisher is None
                and (self.artifact_id is None or self.artifact_id.startswith("family:"))
            )
        if not valid:
            raise NativePolicySnapshotError("native_policy_authority_scope_invalid")

    @property
    def requires_exact_context(self) -> bool:
        return (
            self.source_kind is NativePolicySourceKind.LOCAL
            and self.scope in {NativePolicyScope.HARNESS, NativePolicyScope.GLOBAL}
            and self.artifact_id is not None
            and self.artifact_id.removeprefix("family:") in _EXACT_CONTEXT_FAMILIES
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "harness": self.harness,
            "scope": self.scope.value,
            "action": self.action.value,
            "source_kind": self.source_kind.value,
            "updated_at_us": self.updated_at_us,
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "workspace": self.workspace,
            "publisher": self.publisher,
            "expires_at_ms": self.expires_at_ms,
            "exact_command_sha256": self.exact_command_sha256,
            "requires_exact_context": self.requires_exact_context,
        }


@dataclass(frozen=True, slots=True, repr=False)
class NativeManagedControl:
    target_kind: str
    target_id: str
    state: str

    def __post_init__(self) -> None:
        _ = bounded_authority_text(self.target_id)
        _ = bounded_authority_text(self.target_kind)
        _ = bounded_authority_text(self.state)
        if self.target_kind not in {"extension", "permission"} or self.state not in {"enabled", "disabled"}:
            raise NativePolicySnapshotError("native_policy_authority_control_invalid")
        if _CONTROL_TARGET.fullmatch(self.target_id) is None or (
            (self.target_kind == "permission") != (".permission." in self.target_id)
        ):
            raise NativePolicySnapshotError("native_policy_authority_control_invalid")

    def to_mapping(self) -> dict[str, object]:
        return {"target_kind": self.target_kind, "target_id": self.target_id, "state": self.state}


@dataclass(frozen=True, slots=True, repr=False)
class NativeManagedPolicyAuthority:
    revision: int
    managed_revision: int
    catalog_digest: str
    global_lockdown: bool
    controls: tuple[NativeManagedControl, ...]

    def __post_init__(self) -> None:
        _ = authority_integer(self.revision)
        _ = authority_integer(self.managed_revision)
        _ = bounded_authority_text(self.catalog_digest)
        if len(self.catalog_digest) != 64 or any(ch not in "0123456789abcdef" for ch in self.catalog_digest):
            raise NativePolicySnapshotError("native_policy_authority_catalog_invalid")
        if (
            type(self.global_lockdown) is not bool
            or type(self.controls) is not tuple
            or len(self.controls) > NATIVE_AUTHORITY_MAX_CONTROLS
        ):
            raise NativePolicySnapshotError("native_policy_authority_control_invalid")
        if any(type(item) is not NativeManagedControl for item in self.controls):
            raise NativePolicySnapshotError("native_policy_authority_control_invalid")
        identities = [(item.target_kind, item.target_id) for item in self.controls]
        if len(set(identities)) != len(identities):
            raise NativePolicySnapshotError("native_policy_authority_control_duplicate")

    def to_mapping(self) -> dict[str, object]:
        return {
            "revision": self.revision,
            "managed_revision": self.managed_revision,
            "catalog_digest": self.catalog_digest,
            "global_lockdown": self.global_lockdown,
            "controls": [control.to_mapping() for control in self.controls],
        }


@dataclass(frozen=True, slots=True, repr=False)
class NativePolicyAuthorityDraft:
    rows: tuple[NativeScopedPolicyRow, ...]
    managed: NativeManagedPolicyAuthority | None = None
    command_expressions: tuple[NativeScopedCommandExpression, ...] = ()
    managed_config: NativeManagedConfiguration | None = None

    def __post_init__(self) -> None:
        if type(self.rows) is not tuple or len(self.rows) > NATIVE_AUTHORITY_MAX_ROWS:
            raise NativePolicySnapshotError("native_policy_authority_row_limit")
        if any(type(row) is not NativeScopedPolicyRow for row in self.rows):
            raise NativePolicySnapshotError("native_policy_authority_row_invalid")
        if len({row.decision_id for row in self.rows}) != len(self.rows):
            raise NativePolicySnapshotError("native_policy_authority_row_duplicate")
        if self.managed is not None and type(self.managed) is not NativeManagedPolicyAuthority:
            raise NativePolicySnapshotError("native_policy_authority_control_invalid")
        if self.managed_config is not None and type(self.managed_config) is not NativeManagedConfiguration:
            raise NativePolicySnapshotError("native_policy_managed_configuration_invalid")
        if type(self.command_expressions) is not tuple or len(self.command_expressions) > len(self.rows):
            raise NativePolicySnapshotError("native_policy_authority_command_expression_invalid")
        by_id = {row.decision_id: row for row in self.rows}
        seen: set[int] = set()
        for binding in self.command_expressions:
            if type(binding) is not NativeScopedCommandExpression:
                raise NativePolicySnapshotError("native_policy_authority_command_expression_invalid")
            row = by_id.get(binding.decision_id)
            if (
                row is None
                or row.source_kind is not NativePolicySourceKind.SIGNED_BUNDLE
                or binding.decision_id in seen
            ):
                raise NativePolicySnapshotError("native_policy_authority_command_expression_invalid")
            seen.add(binding.decision_id)
        if len(_canonical_json_bytes_v3(self._payload())) > NATIVE_AUTHORITY_MAX_BYTES:
            raise NativePolicySnapshotError("native_policy_authority_byte_limit")

    def _payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": NATIVE_POLICY_AUTHORITY_SCHEMA,
            "generic_precedence": "specificity-recency.v1",
            "rows": [row.to_mapping() for row in sorted(self.rows, key=lambda item: item.decision_id)],
            "managed": self.managed.to_mapping() if self.managed is not None else None,
        }
        if self.command_expressions:
            payload["command_expressions"] = [binding.to_mapping() for binding in self.command_expressions]
        if self.managed_config is not None:
            payload["managed_config"] = self.managed_config.to_mapping()
        return payload

    @property
    def content_digest(self) -> str:
        return _digest_v3(self._payload())

    def for_snapshot(self, capabilities: NativePolicyAuthorityCapabilities) -> dict[str, object]:
        capabilities.require(
            managed=self.managed is not None,
            command_expressions=bool(self.command_expressions),
            managed_config=self.managed_config is not None,
        )
        if self.managed is not None and capabilities.catalog_digest != self.managed.catalog_digest:
            raise NativePolicySnapshotError("native_policy_authority_catalog_mismatch")
        # Return fresh nested containers so the immutable draft cannot be
        # changed by a snapshot encoder retaining a mutable mapping.
        return self._payload()


__all__ = [
    "NATIVE_AUTHORITY_MAX_ROWS",
    "NATIVE_MANAGED_AUTHORITY_FEATURE",
    "NATIVE_SCOPED_AUTHORITY_FEATURE",
    "NativeManagedControl",
    "NativeManagedPolicyAuthority",
    "NativePolicyAction",
    "NativePolicyAuthorityCapabilities",
    "NativePolicyAuthorityDraft",
    "NativePolicyScope",
    "NativePolicySourceKind",
    "NativeScopedPolicyRow",
    "authority_integer",
    "bounded_authority_text",
]
