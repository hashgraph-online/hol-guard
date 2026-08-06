"""Deterministic Linux artifact lifecycle acceptance contracts.

This module consumes ownership-verification receipts; it does not establish their
provenance. Callers must obtain receipts from ``verify_linux_artifact_ownership``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import framed_digest
from codex_plugin_scanner.guard.runtime.linux_artifact_ownership import (
    LinuxArtifactMetadata,
    LinuxArtifactOwnershipReceipt,
    verify_linux_artifact_ownership,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_MAX_MODE = 0o7777
_ROOT_TRUSTED_UIDS = frozenset({0})
_LIFECYCLE_SEAL_KEY = secrets.token_bytes(32)


class LinuxArtifactLifecycleError(ValueError):
    """Raised when a lifecycle transition cannot be accepted safely."""


class LinuxArtifactLifecycleOperation(str, Enum):
    INSTALL = "install"
    UPGRADE = "upgrade"
    REMOVE = "remove"
    REPAIR = "repair"


class LinuxArtifactLifecycleOutcome(str, Enum):
    ACTIVATED = "activated"
    UPGRADED = "upgraded"
    REMOVED = "removed"
    RESTORED = "restored"
    VERIFIED = "verified"


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise LinuxArtifactLifecycleError(f"invalid-{label}")
    return value


def _require_nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise LinuxArtifactLifecycleError(f"invalid-{label}")
    return value


def _require_text(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise LinuxArtifactLifecycleError(f"invalid-{label}")
    return value


@dataclass(frozen=True, slots=True)
class LinuxArtifactIdentity:
    component_id: str
    version: str
    source: str
    license_id: str
    release_sequence: int
    path: str
    device: int
    inode: int
    uid: int
    mode: int
    size: int
    sha256: str
    identity_digest: str
    _provenance_seal: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        for label, value in (
            ("component-id", self.component_id),
            ("version", self.version),
            ("source", self.source),
            ("license-id", self.license_id),
        ):
            _ = _require_text(value, label)
        _ = _require_nonnegative_int(self.release_sequence, "release-sequence")
        _ = _require_artifact_path(self.path)
        for label, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("uid", self.uid),
            ("size", self.size),
        ):
            _ = _require_nonnegative_int(value, label)
        mode = _require_nonnegative_int(self.mode, "mode")
        if mode > _MAX_MODE:
            raise LinuxArtifactLifecycleError("invalid-mode")
        _ = _require_digest(self.sha256, "sha256")
        identity_digest = _require_digest(self.identity_digest, "identity-digest")
        expected_seal = hmac.new(_LIFECYCLE_SEAL_KEY, identity_digest.encode(), hashlib.sha256).digest()
        if type(self._provenance_seal) is not bytes or len(self._provenance_seal) != hashlib.sha256().digest_size:
            raise LinuxArtifactLifecycleError("identity-provenance-invalid")
        if not hmac.compare_digest(self._provenance_seal, expected_seal):
            raise LinuxArtifactLifecycleError("identity-provenance-invalid")
        if self.identity_digest != _identity_digest(self):
            raise LinuxArtifactLifecycleError("artifact-identity-digest-mismatch")


@dataclass(frozen=True, slots=True)
class LinuxArtifactLifecycleState:
    active: LinuxArtifactIdentity | None = None
    rollback: LinuxArtifactIdentity | None = None

    def __post_init__(self) -> None:
        if self.active is not None and type(self.active) is not LinuxArtifactIdentity:
            raise LinuxArtifactLifecycleError("invalid-active-artifact")
        if self.rollback is not None and type(self.rollback) is not LinuxArtifactIdentity:
            raise LinuxArtifactLifecycleError("invalid-rollback-artifact")
        if self.active is None and self.rollback is not None:
            raise LinuxArtifactLifecycleError("rollback-without-active-artifact")
        if self.active is not None and self.rollback is not None:
            if self.active.component_id != self.rollback.component_id:
                raise LinuxArtifactLifecycleError("rollback-component-mismatch")
            if self.active.identity_digest == self.rollback.identity_digest:
                raise LinuxArtifactLifecycleError("duplicate-rollback-artifact")


@dataclass(frozen=True, slots=True)
class LinuxArtifactLifecycleReceipt:
    operation: LinuxArtifactLifecycleOperation
    outcome: LinuxArtifactLifecycleOutcome
    component_id: str
    before_identity_digest: str | None
    after_identity_digest: str | None
    rollback_identity_digest: str | None
    receipt_digest: str
    _provenance_seal: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.operation) is not LinuxArtifactLifecycleOperation:
            raise LinuxArtifactLifecycleError("invalid-operation")
        if type(self.outcome) is not LinuxArtifactLifecycleOutcome:
            raise LinuxArtifactLifecycleError("invalid-outcome")
        _ = _require_text(self.component_id, "component-id")
        for label, value in (
            ("before-identity-digest", self.before_identity_digest),
            ("after-identity-digest", self.after_identity_digest),
            ("rollback-identity-digest", self.rollback_identity_digest),
        ):
            if value is not None:
                _ = _require_digest(value, label)
        valid_outcomes = {
            LinuxArtifactLifecycleOperation.INSTALL: {LinuxArtifactLifecycleOutcome.ACTIVATED},
            LinuxArtifactLifecycleOperation.UPGRADE: {LinuxArtifactLifecycleOutcome.UPGRADED},
            LinuxArtifactLifecycleOperation.REMOVE: {LinuxArtifactLifecycleOutcome.REMOVED},
            LinuxArtifactLifecycleOperation.REPAIR: {
                LinuxArtifactLifecycleOutcome.RESTORED,
                LinuxArtifactLifecycleOutcome.VERIFIED,
            },
        }
        if self.outcome not in valid_outcomes[self.operation]:
            raise LinuxArtifactLifecycleError("invalid-operation-outcome")
        if self.operation is LinuxArtifactLifecycleOperation.INSTALL:
            valid_shape = (
                self.before_identity_digest is None
                and self.after_identity_digest is not None
                and self.rollback_identity_digest is None
            )
        elif self.operation is LinuxArtifactLifecycleOperation.UPGRADE:
            valid_shape = (
                self.before_identity_digest is not None
                and self.after_identity_digest is not None
                and self.rollback_identity_digest == self.before_identity_digest
                and self.before_identity_digest != self.after_identity_digest
            )
        elif self.operation is LinuxArtifactLifecycleOperation.REMOVE:
            valid_shape = (
                self.before_identity_digest is not None
                and self.after_identity_digest is None
                and self.rollback_identity_digest is None
            )
        elif self.outcome is LinuxArtifactLifecycleOutcome.VERIFIED:
            valid_shape = (
                self.before_identity_digest is not None and self.after_identity_digest == self.before_identity_digest
            )
        else:
            valid_shape = (
                self.after_identity_digest is not None and self.before_identity_digest != self.after_identity_digest
            )
        if not valid_shape:
            raise LinuxArtifactLifecycleError("invalid-evidence-shape")
        if self.receipt_digest != _receipt_digest(
            operation=self.operation,
            outcome=self.outcome,
            component_id=self.component_id,
            before=self.before_identity_digest,
            after=self.after_identity_digest,
            rollback=self.rollback_identity_digest,
        ):
            raise LinuxArtifactLifecycleError("lifecycle-receipt-digest-mismatch")
        if type(self._provenance_seal) is not bytes or len(self._provenance_seal) != hashlib.sha256().digest_size:
            raise LinuxArtifactLifecycleError("receipt-provenance-invalid")
        expected_seal = hmac.new(_LIFECYCLE_SEAL_KEY, self.receipt_digest.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(self._provenance_seal, expected_seal):
            raise LinuxArtifactLifecycleError("receipt-provenance-invalid")


@dataclass(frozen=True, slots=True)
class LinuxArtifactLifecycleTransition:
    state: LinuxArtifactLifecycleState
    receipt: LinuxArtifactLifecycleReceipt

    def __post_init__(self) -> None:
        if type(self.state) is not LinuxArtifactLifecycleState:
            raise LinuxArtifactLifecycleError("invalid-transition-state")
        if type(self.receipt) is not LinuxArtifactLifecycleReceipt:
            raise LinuxArtifactLifecycleError("invalid-transition-receipt")
        active_digest = self.state.active.identity_digest if self.state.active is not None else None
        rollback_digest = self.state.rollback.identity_digest if self.state.rollback is not None else None
        if (
            self.receipt.after_identity_digest != active_digest
            or self.receipt.rollback_identity_digest != rollback_digest
        ):
            raise LinuxArtifactLifecycleError("transition-state-mismatch")
        if self.state.active is not None and self.receipt.component_id != self.state.active.component_id:
            raise LinuxArtifactLifecycleError("transition-component-mismatch")


def _require_artifact_path(value: object) -> str:
    path = _require_text(value, "path")
    if "\x00" in path or path.startswith("//"):
        raise LinuxArtifactLifecycleError("invalid-path")
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or str(parsed) != path or any(part in {".", ".."} for part in parsed.parts):
        raise LinuxArtifactLifecycleError("invalid-path")
    return path


def _identity_fields(identity: LinuxArtifactIdentity) -> dict[str, object]:
    return {
        "component_id": identity.component_id,
        "device": identity.device,
        "inode": identity.inode,
        "license_id": identity.license_id,
        "release_sequence": identity.release_sequence,
        "mode": identity.mode,
        "path": identity.path,
        "sha256": identity.sha256,
        "size": identity.size,
        "source": identity.source,
        "uid": identity.uid,
        "version": identity.version,
    }


def _identity_digest(identity: LinuxArtifactIdentity) -> str:
    return framed_digest("guard.linux-artifact-identity.v1", _identity_fields(identity))


def _identity_from_verified_receipt(
    receipt: LinuxArtifactOwnershipReceipt,
) -> LinuxArtifactIdentity:
    """Convert verifier output into a lifecycle-bound identity."""
    if type(receipt) is not LinuxArtifactOwnershipReceipt:
        raise LinuxArtifactLifecycleError("invalid-ownership-receipt")
    metadata = receipt.metadata
    if type(metadata) is not LinuxArtifactMetadata:
        raise LinuxArtifactLifecycleError("invalid-artifact-metadata")
    component_id = _require_text(metadata.component_id, "component-id")
    version = _require_text(metadata.version, "version")
    source = _require_text(metadata.source, "source")
    license_id = _require_text(metadata.license_id, "license-id")
    release_sequence = _require_nonnegative_int(metadata.release_sequence, "release-sequence")
    expected_sha256 = _require_digest(metadata.expected_sha256, "expected-sha256")
    sha256 = _require_digest(receipt.sha256, "sha256")
    if expected_sha256 != sha256:
        raise LinuxArtifactLifecycleError("ownership-receipt-digest-mismatch")
    path = _require_artifact_path(receipt.path)
    device = _require_nonnegative_int(receipt.device, "device")
    inode = _require_nonnegative_int(receipt.inode, "inode")
    uid = _require_nonnegative_int(receipt.uid, "uid")
    mode = _require_nonnegative_int(receipt.mode, "mode")
    if mode > _MAX_MODE:
        raise LinuxArtifactLifecycleError("invalid-mode")
    size = _require_nonnegative_int(receipt.size, "size")
    fields = {
        "component_id": component_id,
        "device": device,
        "inode": inode,
        "license_id": license_id,
        "release_sequence": release_sequence,
        "mode": mode,
        "path": path,
        "sha256": sha256,
        "size": size,
        "source": source,
        "uid": uid,
        "version": version,
    }
    identity_digest = framed_digest("guard.linux-artifact-identity.v1", fields)
    return LinuxArtifactIdentity(
        component_id=component_id,
        version=version,
        source=source,
        release_sequence=release_sequence,
        license_id=license_id,
        path=path,
        device=device,
        inode=inode,
        uid=uid,
        mode=mode,
        size=size,
        sha256=sha256,
        identity_digest=identity_digest,
        _provenance_seal=hmac.new(_LIFECYCLE_SEAL_KEY, identity_digest.encode(), hashlib.sha256).digest(),
    )


def _verify_artifact(
    path: str,
    metadata: LinuxArtifactMetadata,
    expected_uid: int,
    trusted_ancestor_uids: frozenset[int] | None,
) -> LinuxArtifactIdentity:
    if type(metadata) is not LinuxArtifactMetadata:
        raise LinuxArtifactLifecycleError("invalid-artifact-metadata")
    canonical_path = _require_artifact_path(path)
    validated_uid = _require_nonnegative_int(expected_uid, "expected-uid")
    if trusted_ancestor_uids is not None:
        if type(trusted_ancestor_uids) is not frozenset or not trusted_ancestor_uids:
            raise LinuxArtifactLifecycleError("invalid-trusted-ancestor-uids")
        for uid in trusted_ancestor_uids:
            _ = _require_nonnegative_int(uid, "trusted-ancestor-uid")
    trusted_uids = frozenset({0, validated_uid}) if trusted_ancestor_uids is None else trusted_ancestor_uids
    receipt = verify_linux_artifact_ownership(
        canonical_path,
        metadata=metadata,
        expected_uid=validated_uid,
        trusted_ancestor_uids=trusted_uids,
    )
    return _identity_from_verified_receipt(receipt)


def _reverify_identity(
    identity: LinuxArtifactIdentity,
    trusted_ancestor_uids: frozenset[int] | None,
    expected_uid: int,
) -> LinuxArtifactIdentity:
    metadata = LinuxArtifactMetadata(
        component_id=identity.component_id,
        version=identity.version,
        source=identity.source,
        license_id=identity.license_id,
        expected_sha256=identity.sha256,
        release_sequence=identity.release_sequence,
    )
    verified = _verify_artifact(identity.path, metadata, expected_uid, trusted_ancestor_uids)
    if verified != identity:
        raise LinuxArtifactLifecycleError("active-artifact-identity-mismatch")
    return verified


def _receipt_digest(
    *,
    operation: LinuxArtifactLifecycleOperation,
    outcome: LinuxArtifactLifecycleOutcome,
    component_id: str,
    before: str | None,
    after: str | None,
    rollback: str | None,
) -> str:
    return framed_digest(
        "guard.linux-artifact-lifecycle-receipt.v1",
        {
            "after_identity_digest": after or "",
            "before_identity_digest": before or "",
            "component_id": component_id,
            "operation": operation.value,
            "outcome": outcome.value,
            "rollback_identity_digest": rollback or "",
        },
    )


def _transition(
    *,
    operation: LinuxArtifactLifecycleOperation,
    outcome: LinuxArtifactLifecycleOutcome,
    component_id: str,
    before: LinuxArtifactIdentity | None,
    state: LinuxArtifactLifecycleState,
) -> LinuxArtifactLifecycleTransition:
    after = state.active.identity_digest if state.active is not None else None
    rollback = state.rollback.identity_digest if state.rollback is not None else None
    before_digest = before.identity_digest if before is not None else None
    receipt_digest = _receipt_digest(
        operation=operation,
        outcome=outcome,
        component_id=component_id,
        before=before_digest,
        after=after,
        rollback=rollback,
    )
    receipt = LinuxArtifactLifecycleReceipt(
        operation=operation,
        outcome=outcome,
        component_id=component_id,
        before_identity_digest=before_digest,
        after_identity_digest=after,
        rollback_identity_digest=rollback,
        receipt_digest=receipt_digest,
        _provenance_seal=hmac.new(_LIFECYCLE_SEAL_KEY, receipt_digest.encode(), hashlib.sha256).digest(),
    )
    return LinuxArtifactLifecycleTransition(state=state, receipt=receipt)


def install_linux_artifact(
    state: LinuxArtifactLifecycleState,
    path: str,
    metadata: LinuxArtifactMetadata,
    *,
    expected_uid: int,
    trusted_ancestor_uids: frozenset[int] | None = None,
) -> LinuxArtifactLifecycleTransition:
    if type(state) is not LinuxArtifactLifecycleState:
        raise LinuxArtifactLifecycleError("invalid-lifecycle-state")
    if state.active is not None:
        raise LinuxArtifactLifecycleError("install-requires-absent-artifact")
    artifact = _verify_artifact(path, metadata, expected_uid, trusted_ancestor_uids)
    return _transition(
        operation=LinuxArtifactLifecycleOperation.INSTALL,
        outcome=LinuxArtifactLifecycleOutcome.ACTIVATED,
        component_id=artifact.component_id,
        before=None,
        state=LinuxArtifactLifecycleState(active=artifact),
    )


def upgrade_linux_artifact(
    state: LinuxArtifactLifecycleState,
    path: str,
    metadata: LinuxArtifactMetadata,
    *,
    expected_uid: int,
    trusted_ancestor_uids: frozenset[int] | None = None,
) -> LinuxArtifactLifecycleTransition:
    if type(state) is not LinuxArtifactLifecycleState or state.active is None:
        raise LinuxArtifactLifecycleError("upgrade-requires-active-artifact")
    artifact = _verify_artifact(path, metadata, expected_uid, trusted_ancestor_uids)
    previous = _reverify_identity(state.active, trusted_ancestor_uids, expected_uid)
    if artifact.component_id != previous.component_id:
        raise LinuxArtifactLifecycleError("upgrade-component-mismatch")
    if artifact.release_sequence <= previous.release_sequence:
        raise LinuxArtifactLifecycleError("upgrade-requires-newer-release")
    if artifact.identity_digest == previous.identity_digest:
        raise LinuxArtifactLifecycleError("upgrade-requires-different-artifact")
    return _transition(
        operation=LinuxArtifactLifecycleOperation.UPGRADE,
        outcome=LinuxArtifactLifecycleOutcome.UPGRADED,
        component_id=artifact.component_id,
        before=previous,
        state=LinuxArtifactLifecycleState(active=artifact, rollback=previous),
    )


def remove_linux_artifact(state: LinuxArtifactLifecycleState) -> LinuxArtifactLifecycleTransition:
    if type(state) is not LinuxArtifactLifecycleState or state.active is None:
        raise LinuxArtifactLifecycleError("remove-requires-active-artifact")
    previous = state.active
    if os.path.lexists(previous.path):
        raise LinuxArtifactLifecycleError("remove-requires-artifact-absence")
    return _transition(
        operation=LinuxArtifactLifecycleOperation.REMOVE,
        outcome=LinuxArtifactLifecycleOutcome.REMOVED,
        component_id=previous.component_id,
        before=previous,
        state=LinuxArtifactLifecycleState(),
    )


def repair_linux_artifact(
    state: LinuxArtifactLifecycleState,
    path: str,
    metadata: LinuxArtifactMetadata,
    *,
    expected_uid: int,
    trusted_ancestor_uids: frozenset[int] | None = None,
) -> LinuxArtifactLifecycleTransition:
    if type(state) is not LinuxArtifactLifecycleState or state.active is None:
        raise LinuxArtifactLifecycleError("repair-requires-active-artifact")
    expected = _verify_artifact(path, metadata, expected_uid, trusted_ancestor_uids)
    before = state.active
    if before.component_id != expected.component_id:
        raise LinuxArtifactLifecycleError("repair-component-mismatch")
    if expected.release_sequence != before.release_sequence:
        raise LinuxArtifactLifecycleError("repair-requires-same-release")
    unchanged = before.identity_digest == expected.identity_digest
    outcome = LinuxArtifactLifecycleOutcome.VERIFIED if unchanged else LinuxArtifactLifecycleOutcome.RESTORED
    return _transition(
        operation=LinuxArtifactLifecycleOperation.REPAIR,
        outcome=outcome,
        component_id=expected.component_id,
        before=before,
        state=LinuxArtifactLifecycleState(active=expected, rollback=state.rollback),
    )


__all__ = [
    "LinuxArtifactIdentity",
    "LinuxArtifactLifecycleError",
    "LinuxArtifactLifecycleOperation",
    "LinuxArtifactLifecycleOutcome",
    "LinuxArtifactLifecycleReceipt",
    "LinuxArtifactLifecycleState",
    "LinuxArtifactLifecycleTransition",
    "install_linux_artifact",
    "remove_linux_artifact",
    "repair_linux_artifact",
    "upgrade_linux_artifact",
]
