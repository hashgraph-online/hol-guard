"""Manifest and lockfile target derivation for package install evaluation."""

from __future__ import annotations

import importlib
from pathlib import Path

from ..models import GuardArtifact
from .workspace_path_guard import read_bytes_within_workspace, read_text_within_workspace, resolve_path_within_workspace

_MANIFEST_ECOSYSTEMS = {
    "package.json": "npm",
    "pyproject.toml": "pypi",
    "requirements.txt": "pypi",
    "pipfile": "pypi",
    "cargo.toml": "cargo",
    "go.mod": "go",
    "composer.json": "packagist",
    "gemfile": "rubygems",
}


def _supply_chain_package_eval_module():
    return importlib.import_module(".supply_chain_package_eval", __package__)


def _manifest_ecosystem_for_path(path: str) -> str | None:
    manifest_name = Path(path).name.lower()
    return _MANIFEST_ECOSYSTEMS.get(manifest_name)


def evaluation_targets(
    artifact: GuardArtifact,
    workspace_dir: Path | None,
    *,
    explicit_targets: tuple[dict[str, object], ...],
    include_locked: bool = False,
) -> tuple[dict[str, object], ...]:
    if explicit_targets:
        return explicit_targets
    intent_kind = _supply_chain_package_eval_module()._optional_string(artifact.metadata.get("intent_kind"))
    if intent_kind not in {None, "install", "sync"}:
        return ()
    return _manifest_dependency_targets(artifact, workspace_dir, include_locked=include_locked)


def unsynced_manifest_dependency_targets(
    artifact: GuardArtifact,
    workspace_dir: Path | None,
) -> tuple[dict[str, object], ...]:
    return _manifest_dependency_targets(artifact, workspace_dir, include_locked=False)


def _manifest_dependency_targets(
    artifact: GuardArtifact,
    workspace_dir: Path | None,
    *,
    include_locked: bool,
) -> tuple[dict[str, object], ...]:
    if workspace_dir is None:
        return ()
    package_eval = _supply_chain_package_eval_module()

    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list) or not manifest_paths:
        return ()
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    redacted_command = package_eval._optional_string(artifact.metadata.get("redacted_command"))
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    lockfile_dependencies: list[tuple[Path, str, dict[str, str]]] = []
    if isinstance(lockfile_paths, list):
        for relative_path in lockfile_paths:
            if not isinstance(relative_path, str) or not relative_path:
                continue
            lockfile_path = resolve_path_within_workspace(workspace_dir, relative_path)
            if lockfile_path is None:
                continue
            lockfile_source = read_bytes_within_workspace(workspace_dir, relative_path)
            if lockfile_source is None:
                continue
            lockfile_ecosystem = package_eval._lockfile_ecosystem(lockfile_path.name) or "npm"
            versions: dict[str, str] = {}
            parse_result = package_eval._parse_lockfile_text_result(lockfile_path.name, lockfile_source)
            for package_name, version in parse_result.manifest_dependency_map().items():
                normalized_name = package_eval._normalize_package_name(lockfile_ecosystem, package_name)
                versions[normalized_name] = version
            lockfile_dependencies.append((lockfile_path.parent, lockfile_ecosystem, versions))
    unsynced_targets: list[dict[str, object]] = []
    for relative_path in manifest_paths:
        if not isinstance(relative_path, str) or not relative_path:
            continue
        ecosystem = _manifest_ecosystem_for_path(relative_path)
        if ecosystem is None:
            continue
        manifest_path = resolve_path_within_workspace(workspace_dir, relative_path)
        if manifest_path is None:
            continue
        manifest_text = read_text_within_workspace(workspace_dir, relative_path)
        if manifest_text is None:
            continue
        dependency_map = package_eval._artifact_manifest_dependency_map(
            package_manager=package_manager,
            relative_path=relative_path,
            manifest_text=manifest_text,
        )
        applicable_lockfiles = [
            (lockfile_parent, versions)
            for lockfile_parent, lockfile_ecosystem, versions in lockfile_dependencies
            if lockfile_ecosystem == ecosystem
            and (lockfile_parent == manifest_path.parent or lockfile_parent in manifest_path.parent.parents)
        ]
        if applicable_lockfiles:
            closest_depth = max(len(parent.parts) for parent, _versions in applicable_lockfiles)
            scoped_lockfiles = [
                versions for parent, versions in applicable_lockfiles if len(parent.parts) == closest_depth
            ]
        else:
            scoped_lockfiles = []
        lockfile_versions: dict[str, str | None] = {}
        for versions in scoped_lockfiles:
            for normalized_name, version in versions.items():
                if normalized_name not in lockfile_versions:
                    lockfile_versions[normalized_name] = version
                elif lockfile_versions[normalized_name] != version:
                    lockfile_versions[normalized_name] = None
        for package_name, specifier in dependency_map.items():
            normalized_name = package_eval._normalize_package_name(ecosystem, package_name)
            locked_version = lockfile_versions.get(normalized_name)
            if not include_locked and locked_version is not None:
                continue
            namespace, name = package_eval._split_namespace_name(package_name, ecosystem=ecosystem)
            exact_version = (locked_version if include_locked else None) or package_eval._manifest_exact_version(
                ecosystem, specifier
            )
            unsynced_targets.append(
                {
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "normalized_name": normalized_name,
                    "namespace": namespace,
                    "name": name,
                    "raw_spec": package_name if exact_version is None else f"{package_name}@{exact_version}",
                    "version": exact_version,
                    "range": specifier if exact_version is None else None,
                    "source_url": package_eval._source_url_from_specifier(specifier),
                    "alias": None,
                    "dependency_group": None,
                    "extras": (),
                    "editable": False,
                    "package_manager": package_manager,
                    "redacted_command": redacted_command,
                    "manifest_unsynced": locked_version is None,
                }
            )
    return tuple(unsynced_targets)
