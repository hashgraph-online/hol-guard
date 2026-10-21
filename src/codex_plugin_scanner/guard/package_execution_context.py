"""Security-complete identities for reusable package approvals.

Package approvals are reusable only when Guard can bind the request to a Git
repository and to every local input that can materially change package-manager
execution. The evidence representation contains digests and stable labels,
never registry credentials or configuration contents.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .models import GuardArtifact
from .native_context import context_package_evidence
from .native_package_context_build import native_build_package_context

PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND: Final = "package_execution_context"
PACKAGE_EXECUTION_CONTEXT_VERSION: Final = 2


@dataclass(frozen=True, slots=True)
class PackageExecutionContextComponent:
    """One safely displayable component of a package execution identity."""

    name: str
    digest: str


@dataclass(frozen=True, slots=True)
class PackageExecutionContext:
    """Versioned package-manager execution context."""

    digest: str
    portable: bool
    components: tuple[PackageExecutionContextComponent, ...]
    non_portable_reason: str | None = None
    version: int = PACKAGE_EXECUTION_CONTEXT_VERSION

    def to_evidence(self, *, changed_components: Sequence[str] = ()) -> dict[str, object]:
        payload: dict[str, object] = {
            "kind": PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND,
            "schema_version": self.version,
            "portable": self.portable,
            "context_digest": self.digest,
            "components": [{"name": component.name, "digest": component.digest} for component in self.components],
            "portable_summary": (
                "Reusable only across linked Git worktrees when every package execution input matches."
                if self.portable
                else "Bound to this retry because Guard could not prove a complete portable package context."
            ),
        }
        if self.non_portable_reason is not None:
            payload["non_portable_reason"] = self.non_portable_reason
        normalized_changes = tuple(dict.fromkeys(item for item in changed_components if item))
        if normalized_changes:
            payload["changed_components"] = list(normalized_changes)
        return payload


def build_package_execution_context(
    *,
    workspace_dir: Path,
    artifact: GuardArtifact,
    executable: str | None = None,
    executable_args: Sequence[str] = (),
    environment: Mapping[str, str] | None = None,
) -> PackageExecutionContext:
    """Build a fail-closed package execution context through the native resident."""

    context = native_build_package_context(
        workspace_dir=workspace_dir,
        metadata=artifact.metadata,
        executable=executable,
        executable_args=executable_args,
        environment=environment,
    )
    built = _project_native_package_context(context)
    if built is None:
        raise ValueError("native_package_context_build_malformed")
    return built


def _project_native_package_context(context: dict[str, Any] | None) -> PackageExecutionContext | None:
    if context is None:
        return None
    return PackageExecutionContext(
        digest=context["digest"],
        portable=context["portable"],
        components=tuple(
            PackageExecutionContextComponent(name=item["name"], digest=item["digest"]) for item in context["components"]
        ),
        non_portable_reason=context["non_portable_reason"],
    )


def package_execution_context_from_evidence(value: object) -> PackageExecutionContext | None:
    """Project native validation of persisted package context evidence."""

    return _project_native_package_context(context_package_evidence(value))


def package_execution_context_from_scanner_evidence(value: object) -> PackageExecutionContext | None:
    return _project_native_package_context(context_package_evidence(value, scanner_evidence=True))


def changed_package_execution_context_components(
    previous: PackageExecutionContext,
    current: PackageExecutionContext,
) -> tuple[str, ...]:
    previous_components = {item.name: item.digest for item in previous.components}
    current_components = {item.name: item.digest for item in current.components}
    return tuple(
        sorted(
            name
            for name in previous_components.keys() | current_components.keys()
            if previous_components.get(name) != current_components.get(name)
        )
    )


__all__ = [
    "PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND",
    "PACKAGE_EXECUTION_CONTEXT_VERSION",
    "PackageExecutionContext",
    "PackageExecutionContextComponent",
    "build_package_execution_context",
    "changed_package_execution_context_components",
    "package_execution_context_from_evidence",
    "package_execution_context_from_scanner_evidence",
]
