"""Immutable, in-memory extension-control state for hot-path decisions."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from .extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .extension_control_contract import ExtensionControlLayer, ResolverFailureCode

_RUNTIME_SNAPSHOT_SCHEMA = "guard.extension-control-runtime-snapshot.v1"
_NO_CONTROL_DIGEST = hashlib.sha256(b"hol.guard.extension-control:none:v1").hexdigest()
_ACTIVE_SNAPSHOT: ContextVar[ExtensionControlRuntimeSnapshot | None] = ContextVar(
    "guard_extension_control_runtime_snapshot",
    default=None,
)


@dataclass(frozen=True, slots=True)
class ExtensionControlDecisionEvidence:
    revision: int
    effective_digest: str

    def __repr__(self) -> str:
        return "ExtensionControlDecisionEvidence(<private>)"


@dataclass(frozen=True, slots=True)
class ExtensionControlRuntimeSnapshot:
    health: AuthorityHealth
    revision: int
    catalog_digest: str
    effective_digest: str
    layers: tuple[ExtensionControlLayer, ...]

    @classmethod
    def from_authority_view(cls, view: ExtensionControlAuthorityView) -> ExtensionControlRuntimeSnapshot:
        payload = {
            "catalog_digest": view.catalog_digest,
            "health": view.health.value,
            "layers": sorted(
                (_layer_payload(layer) for layer in view.layers),
                key=lambda item: str(item["kind"]),
            ),
            "revision": view.revision,
            "schema_version": _RUNTIME_SNAPSHOT_SCHEMA,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        framed = f"{_RUNTIME_SNAPSHOT_SCHEMA}\x00{len(canonical)}\x00{canonical}"
        return cls(
            health=view.health,
            revision=view.revision,
            catalog_digest=view.catalog_digest,
            effective_digest=hashlib.sha256(framed.encode("utf-8")).hexdigest(),
            layers=view.layers,
        )

    @property
    def authority_failure(self) -> ResolverFailureCode | None:
        if self.health is AuthorityHealth.PROTECTED:
            return None
        if self.health in {AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED}:
            return ResolverFailureCode.AUTHORITY_TAMPERED
        return ResolverFailureCode.AUTHORITY_UNAVAILABLE

    @property
    def private_evidence(self) -> ExtensionControlDecisionEvidence:
        return ExtensionControlDecisionEvidence(self.revision, self.effective_digest)


class ExtensionControlRuntime:
    """Own one immutable snapshot and swap it atomically after mutations."""

    def __init__(self, initial: ExtensionControlAuthorityView) -> None:
        self._lock = threading.Lock()
        self._snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(initial)
        self._highest_protected_revision = (
            initial.revision if initial.health is AuthorityHealth.PROTECTED else 0
        )
        self._highest_protected_digest = (
            self._snapshot.effective_digest if initial.health is AuthorityHealth.PROTECTED else None
        )

    def current(self) -> ExtensionControlRuntimeSnapshot:
        return self._snapshot

    def refresh(self, view: ExtensionControlAuthorityView) -> ExtensionControlRuntimeSnapshot:
        candidate = ExtensionControlRuntimeSnapshot.from_authority_view(view)
        with self._lock:
            if candidate.health is not AuthorityHealth.PROTECTED:
                self._snapshot = candidate
                return candidate
            if candidate.revision < self._highest_protected_revision:
                raise ValueError("extension control runtime revision cannot move backwards")
            if (
                candidate.revision == self._highest_protected_revision
                and self._highest_protected_digest is not None
                and candidate.effective_digest != self._highest_protected_digest
            ):
                raise ValueError("extension control runtime revision cannot be replaced")
            self._highest_protected_digest = candidate.effective_digest
            self._highest_protected_revision = candidate.revision
            self._snapshot = candidate
            return candidate


@contextmanager
def use_extension_control_snapshot(snapshot: ExtensionControlRuntimeSnapshot) -> Iterator[None]:
    token = _ACTIVE_SNAPSHOT.set(snapshot)
    try:
        yield
    finally:
        _ACTIVE_SNAPSHOT.reset(token)


def current_extension_control_snapshot() -> ExtensionControlRuntimeSnapshot | None:
    return _ACTIVE_SNAPSHOT.get()


def current_extension_control_binding_digest() -> str:
    snapshot = current_extension_control_snapshot()
    return _NO_CONTROL_DIGEST if snapshot is None else snapshot.effective_digest


def extension_control_policy_version(base_version: str) -> str:
    if not isinstance(base_version, str) or not base_version.strip():
        raise ValueError("base policy version is required")
    return f"{base_version}@{current_extension_control_binding_digest()}"


def _layer_payload(layer: ExtensionControlLayer) -> dict[str, object]:
    return {
        "catalog_digest": layer.catalog_digest,
        "controls": sorted(
            (
                {
                    "state": control.state.value,
                    "target_id": control.target.target_id,
                    "target_kind": control.target.kind.value,
                }
                for control in layer.controls
            ),
            key=lambda item: (str(item["target_kind"]), str(item["target_id"])),
        ),
        "global_lockdown": layer.global_lockdown,
        "kind": layer.kind.value,
        "schema_version": layer.schema_version,
    }
