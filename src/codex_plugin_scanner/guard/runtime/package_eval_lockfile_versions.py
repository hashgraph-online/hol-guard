"""Package lockfile and manifest version selection."""

from __future__ import annotations


def _lockfile_dependency_versions(
    workspace_dir: _eval.Path | None,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    if workspace_dir is None:
        return {}
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return {}
    versions: dict[tuple[str, str | None], str] = {}
    python_manifest_names = _eval._manifest_direct_dependency_names(
        workspace_dir,
        artifact,
        ecosystem="pypi",
    )
    for relative_path in lockfile_paths:
        lockfile_path = _eval.resolve_path_within_workspace(workspace_dir, str(relative_path))
        if lockfile_path is None:
            continue
        if lockfile_path.name.lower() == "bun.lockb":
            continue
        lockfile_source = _eval.read_bytes_within_workspace(workspace_dir, str(relative_path))
        if lockfile_source is None:
            continue
        parse_result = _eval._parse_lockfile_text_result(lockfile_path.name, lockfile_source)
        if not parse_result.complete:
            continue
        if lockfile_path.name == "package-lock.json":
            versions.update(_eval._package_lock_target_versions_from_entries(parse_result, targets))
            continue
        if lockfile_path.name == "pnpm-lock.yaml":
            versions.update(
                _eval._target_versions_from_direct_map(targets, dict(parse_result.direct_version_candidates))
            )
            continue
        if lockfile_path.name == "yarn.lock":
            versions.update(_eval._yarn_lock_target_versions_from_entries(parse_result, targets))
            continue
        if lockfile_path.name == "bun.lock":
            versions.update(_eval._bun_lock_target_versions(parse_result, targets))
            continue
        if lockfile_path.name in {"Cargo.lock", "composer.lock", "Gemfile.lock"}:
            versions.update(_eval._target_versions_from_direct_map(targets, parse_result.dependency_map()))
            continue
        if lockfile_path.name in {"poetry.lock", "uv.lock", "Pipfile.lock"}:
            direct_versions: dict[str, str] = {}
            for raw_name, raw_version in parse_result.direct_version_candidates:
                name = _eval._optional_string(raw_name)
                version = (
                    _eval._python_lockfile_version(raw_version)
                    if lockfile_path.name == "Pipfile.lock"
                    else _eval._optional_string(raw_version)
                )
                if name is None or version is None:
                    continue
                normalized_name = _eval._normalize_package_name("pypi", name)
                if normalized_name in python_manifest_names:
                    direct_versions[normalized_name] = version
            versions.update(_eval._target_versions_from_direct_map(targets, direct_versions))
    manifest_versions = _eval._manifest_dependency_versions(workspace_dir, artifact, targets)
    for target_key, version in manifest_versions.items():
        versions.setdefault(target_key, version)
    return versions


def _manifest_direct_dependency_names(
    workspace_dir: _eval.Path | None,
    artifact: _eval.GuardArtifact,
    *,
    ecosystem: str,
) -> set[str]:
    if workspace_dir is None:
        return set()
    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list):
        return set()
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    direct_names: set[str] = set()
    for relative_path in manifest_paths:
        manifest_path = _eval.resolve_path_within_workspace(workspace_dir, str(relative_path))
        if manifest_path is None:
            continue
        manifest_text = _eval.read_text_within_workspace(workspace_dir, str(relative_path))
        if manifest_text is None:
            continue
        dependency_map = _eval._artifact_manifest_dependency_map(
            package_manager=package_manager,
            relative_path=str(relative_path),
            manifest_text=manifest_text,
        )
        for package_name in dependency_map:
            direct_names.add(_eval._normalize_package_name(ecosystem, package_name))
    return direct_names


def _manifest_dependency_versions(
    workspace_dir: _eval.Path | None,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    if workspace_dir is None:
        return {}
    manifest_paths = artifact.metadata.get("manifest_paths")
    if not isinstance(manifest_paths, list):
        return {}
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    keyed_targets = {target_key: target for target in targets if (target_key := _eval._lockfile_target_key(target))}
    versions: dict[tuple[str, str | None], str] = {}
    for relative_path in manifest_paths:
        manifest_path = _eval.resolve_path_within_workspace(workspace_dir, str(relative_path))
        if manifest_path is None:
            continue
        manifest_text = _eval.read_text_within_workspace(workspace_dir, str(relative_path))
        if manifest_text is None:
            continue
        dependency_map = _eval._artifact_manifest_dependency_map(
            package_manager=package_manager,
            relative_path=str(relative_path),
            manifest_text=manifest_text,
        )
        if not dependency_map:
            continue
        for target_key, target in keyed_targets.items():
            if target_key in versions:
                continue
            ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
            normalized_dependencies = {
                _eval._normalize_package_name(ecosystem, package_name): specifier
                for package_name, specifier in dependency_map.items()
            }
            for candidate in _eval._target_candidate_names(target):
                specifier = normalized_dependencies.get(_eval._normalize_package_name(ecosystem, candidate))
                exact_version = _eval._manifest_exact_version(ecosystem, specifier)
                if exact_version is not None:
                    versions[target_key] = exact_version
                    break
    return versions


def _artifact_manifest_dependency_map(
    *,
    package_manager: str,
    relative_path: str,
    manifest_text: str,
) -> dict[str, str]:
    dependency_map = _eval.parse_manifest_dependencies(path=relative_path, text=manifest_text)
    if dependency_map or package_manager != "pip":
        return dependency_map
    return _eval.parse_manifest_dependencies(path="requirements.txt", text=manifest_text)


def _package_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    parse_result = _eval._parse_lockfile_text_result("package-lock.json", text)
    if not parse_result.complete:
        return {}
    return _eval._package_lock_target_versions_from_entries(parse_result, targets)


def _package_lock_target_versions_from_entries(
    parse_result: _eval.LockfileParseResult,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    versions: dict[tuple[str, str | None], str] = {}
    for target in targets:
        target_key = _eval._lockfile_target_key(target)
        candidate_paths = set(_eval._package_lock_candidate_names(target))
        normalized_name = str(target["normalized_name"])
        for entry in parse_result.entries:
            if not entry.direct:
                continue
            if entry.dependency_path in candidate_paths or entry.package_name == normalized_name:
                versions[target_key] = entry.version
                break
    return versions


def _package_lock_entries(
    text: str, *, deadline: float | None = None, document: dict[str, object] | None = None
) -> list[tuple[str, str, str, bool]]:
    payload = _eval.json.loads(text or "{}") if document is None else document
    entries: list[tuple[str, str, str, bool]] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, value in packages.items():
            if deadline is not None and _eval.time.monotonic() > deadline:
                raise _eval._DeadlineExceededError("deadline_exceeded")
            if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
                continue
            version = value.get("version") if isinstance(value, dict) else None
            if not isinstance(version, str):
                continue
            dependency_path = package_path.removeprefix("node_modules/")
            package_name = _eval._optional_string(value.get("name")) if isinstance(value, dict) else None
            entries.append(
                (
                    dependency_path,
                    package_name or dependency_path.rsplit("node_modules/", 1)[-1],
                    version,
                    "node_modules/" not in dependency_path,
                )
            )
        return entries
    legacy_dependencies = payload.get("dependencies")
    if isinstance(legacy_dependencies, dict):
        _eval._walk_package_lock_entries(legacy_dependencies, entries, prefix=None, deadline=deadline)
    return entries


def _walk_package_lock_entries(
    payload: dict[str, object],
    entries: list[tuple[str, str, str, bool]],
    *,
    prefix: str | None,
    deadline: float | None,
) -> None:
    for package_name, value in payload.items():
        if deadline is not None and _eval.time.monotonic() > deadline:
            raise _eval._DeadlineExceededError("deadline_exceeded")
        if not isinstance(package_name, str) or not isinstance(value, dict):
            continue
        version = value.get("version")
        dependency_path = package_name if prefix is None else f"{prefix}/node_modules/{package_name}"
        if isinstance(version, str):
            entries.append(
                (
                    dependency_path,
                    _eval._optional_string(value.get("name")) or package_name,
                    version,
                    prefix is None,
                )
            )
        nested_dependencies = value.get("dependencies")
        if isinstance(nested_dependencies, dict):
            _eval._walk_package_lock_entries(nested_dependencies, entries, prefix=dependency_path, deadline=deadline)


def _package_lock_candidate_names(target: dict[str, object]) -> tuple[str, ...]:
    alias = _eval._optional_string(target.get("alias"))
    namespace = _eval._optional_string(target.get("namespace"))
    name = str(target["name"])
    candidates: list[str] = []
    if alias is not None:
        candidates.append(alias)
    qualified_name = f"{namespace}/{name}" if namespace is not None else name
    if qualified_name not in candidates:
        candidates.append(qualified_name)
    return tuple(candidates)


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
