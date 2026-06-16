"""Manifest and lockfile target derivation for package install evaluation."""

from __future__ import annotations

import importlib
from pathlib import Path

from ..models import GuardArtifact
from .package_manifest_diff import parse_manifest_dependencies
from .workspace_path_guard import read_text_within_workspace, resolve_path_within_workspace

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
) -> tuple[dict[str, object], ...]:
    if explicit_targets:
        return explicit_targets
    intent_kind = _supply_chain_package_eval_module()._optional_string(artifact.metadata.get("intent_kind"))
    if intent_kind not in {None, "install", "sync"}:
        return ()
    return unsynced_manifest_dependency_targets(artifact, workspace_dir)


def unsynced_manifest_dependency_targets(
    artifact: GuardArtifact,
    workspace_dir: Path | None,
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
    lockfile_names: set[str] = set()
    if isinstance(lockfile_paths, list):
        for relative_path in lockfile_paths:
            if not isinstance(relative_path, str) or not relative_path:
                continue
            lockfile_path = resolve_path_within_workspace(workspace_dir, relative_path)
            if lockfile_path is None or not lockfile_path.exists():
                continue
            lockfile_text = read_text_within_workspace(workspace_dir, relative_path)
            if lockfile_text is None:
                continue
            lockfile_ecosystem = package_eval._lockfile_ecosystem(lockfile_path.name) or "npm"
            for package_name in parse_manifest_dependencies(path=relative_path, text=lockfile_text):
                lockfile_names.add(package_eval._normalize_package_name(lockfile_ecosystem, package_name))
    unsynced_targets: list[dict[str, object]] = []
    for relative_path in manifest_paths:
        if not isinstance(relative_path, str) or not relative_path:
            continue
        ecosystem = _manifest_ecosystem_for_path(relative_path)
        if ecosystem is None:
            continue
        manifest_path = resolve_path_within_workspace(workspace_dir, relative_path)
        if manifest_path is None or not manifest_path.exists():
            continue
        manifest_text = read_text_within_workspace(workspace_dir, relative_path)
        if manifest_text is None:
            continue
        dependency_map = package_eval._artifact_manifest_dependency_map(
            package_manager=package_manager,
            relative_path=relative_path,
            manifest_text=manifest_text,
        )
        for package_name, specifier in dependency_map.items():
            normalized_name = package_eval._normalize_package_name(ecosystem, package_name)
            if normalized_name in lockfile_names:
                continue
            namespace, name = package_eval._split_namespace_name(package_name)
            exact_version = package_eval._manifest_exact_version(ecosystem, specifier)
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
                    "manifest_unsynced": True,
                }
            )
    return tuple(unsynced_targets)
