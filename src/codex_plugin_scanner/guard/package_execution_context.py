"""Security-complete identities for reusable package approvals.

Package approvals are reusable only when Guard can bind the request to a Git
repository and to every local input that can materially change package-manager
execution. The evidence representation contains digests and stable labels,
never registry credentials or configuration contents.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .models import GuardArtifact
from .package_execution_context_configuration import configuration_material, environment_material
from .package_execution_context_inputs import (
    ContextFiles,
    ContextUnavailableError,
    dependency_material,
    executable_material,
    repository_material,
    workspace_material,
)

PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND: Final = "package_execution_context"
PACKAGE_EXECUTION_CONTEXT_VERSION: Final = 2

_SUPPORTED_PORTABLE_MANAGERS = frozenset(
    {
        "bun",
        "bunx",
        "bundle",
        "bundler",
        "cargo",
        "composer",
        "gem",
        "go",
        "gradle",
        "gradlew",
        "mvn",
        "mvnw",
        "npm",
        "npx",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "pnpm",
        "poetry",
        "uv",
        "uvx",
        "yarn",
    }
)


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
    """Build a fail-closed package execution context for an approval request."""

    workspace = workspace_dir.expanduser().resolve()
    env = dict(os.environ if environment is None else environment)
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    manager = _string_value(metadata.get("package_manager")) or "unknown"
    components: list[PackageExecutionContextComponent] = []
    files = ContextFiles()
    first_failure: str | None = None

    repository_root, repository_identity, repository_failure = repository_material(workspace, files=files)
    if repository_failure is not None:
        first_failure = repository_failure
    components.append(_component("repository_identity", repository_identity))
    workspace_identity = workspace_material(workspace, repository_root, portable=repository_failure is None)
    components.append(_component("workspace_identity", workspace_identity))

    if manager not in _SUPPORTED_PORTABLE_MANAGERS:
        first_failure = first_failure or "unsupported_package_manager"
    if _is_global_request(metadata):
        first_failure = first_failure or "global_package_request"

    executable_identity, executable_failure = executable_material(
        workspace=workspace,
        repository_root=repository_root,
        manager=manager,
        executable=executable or _string_value(metadata.get("package_executable")),
        arguments=executable_args,
        environment=env,
        files=files,
    )
    if executable_failure is not None:
        first_failure = first_failure or executable_failure
    components.append(_component("package_manager_executable", executable_identity))

    dependency_identity, dependency_failure = dependency_material(
        workspace=workspace,
        metadata=metadata,
        files=files,
    )
    if dependency_failure is not None:
        first_failure = first_failure or dependency_failure
    components.append(_component("manifests_and_lockfiles", dependency_identity))

    try:
        configuration = configuration_material(
            workspace=workspace,
            repository_root=repository_root,
            manager=manager,
            environment=env,
            files=files,
        )
    except ContextUnavailableError as error:
        first_failure = first_failure or error.reason
        configuration = {
            "registry_proxy": {"status": error.reason},
            "workspace": {"status": error.reason},
            "hooks_overrides_patches": {"status": error.reason},
            "referenced_environment_names": [],
        }
    components.extend(
        (
            _component("registry_and_proxy_configuration", configuration["registry_proxy"]),
            _component("workspace_configuration", configuration["workspace"]),
            _component("lifecycle_hooks_overrides_and_patches", configuration["hooks_overrides_patches"]),
        )
    )

    referenced_names = configuration.get("referenced_environment_names")
    environment_identity = environment_material(
        manager,
        env,
        referenced_names if isinstance(referenced_names, list) else [],
    )
    components.append(_component("environment_policy", environment_identity))

    portable = first_failure is None
    if not portable:
        components.append(_component("exact_workspace", {"path": str(workspace)}))
    digest = _digest_json(
        {
            "components": [{"name": item.name, "digest": item.digest} for item in components],
            "portable": portable,
            "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
        }
    )
    return PackageExecutionContext(
        digest=digest,
        portable=portable,
        components=tuple(components),
        non_portable_reason=first_failure,
    )


def package_execution_context_from_evidence(value: object) -> PackageExecutionContext | None:
    """Load and strictly validate a package context from persisted safe evidence."""

    if not isinstance(value, Mapping):
        return None
    if value.get("kind") != PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND:
        return None
    if value.get("schema_version") != PACKAGE_EXECUTION_CONTEXT_VERSION:
        return None
    digest = _sha256_value(value.get("context_digest"))
    if digest is None or not isinstance(value.get("portable"), bool):
        return None
    raw_components = value.get("components")
    if not isinstance(raw_components, list):
        return None
    components: list[PackageExecutionContextComponent] = []
    seen: set[str] = set()
    for item in raw_components:
        if not isinstance(item, Mapping):
            return None
        name = _string_value(item.get("name"))
        component_digest = _sha256_value(item.get("digest"))
        if name is None or component_digest is None or name in seen:
            return None
        seen.add(name)
        components.append(PackageExecutionContextComponent(name=name, digest=component_digest))
    if not components:
        return None
    portable = bool(value["portable"])
    expected_digest = _digest_json(
        {
            "components": [{"name": item.name, "digest": item.digest} for item in components],
            "portable": portable,
            "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
        }
    )
    if digest != expected_digest:
        return None
    reason = _string_value(value.get("non_portable_reason"))
    return PackageExecutionContext(
        digest=digest,
        portable=portable,
        components=tuple(components),
        non_portable_reason=reason,
    )


def package_execution_context_from_scanner_evidence(value: object) -> PackageExecutionContext | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return None
    for item in value:
        context = package_execution_context_from_evidence(item)
        if context is not None:
            return context
    return None


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


def _component(name: str, material: object) -> PackageExecutionContextComponent:
    return PackageExecutionContextComponent(name=name, digest=_digest_json(material))


def _digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _string_value(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _sha256_value(value: object) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        return None
    return value


def _is_global_request(metadata: Mapping[str, object]) -> bool:
    flags = _string_items(metadata.get("flags"))
    return any(flag in {"-g", "--global", "--location=global"} or flag.startswith("--global=") for flag in flags)


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
