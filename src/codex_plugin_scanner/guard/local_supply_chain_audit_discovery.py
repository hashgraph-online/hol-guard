"""Audit discovery helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _is_audit_sensitive_basename(name: str) -> bool:
    lowered = name.lower()
    return lowered in _api._AUDIT_SENSITIVE_BASENAMES or lowered.startswith(".env.")


def _read_workspace_audit_text(workspace_dir: _api.Path, relative_path: str) -> str | None:
    if _api._is_audit_sensitive_basename(_api.Path(relative_path).name):
        return None
    return _api.read_text_within_workspace(workspace_dir, relative_path)


def _workspace_has_project_markers(workspace_dir: _api.Path) -> bool:
    try:
        resolved = workspace_dir.resolve()
    except OSError:
        return False
    return any((resolved / marker).exists() for marker in _api._MANIFEST_CANDIDATES)


def managed_install_audit_workspace_dirs(store: _api.Any) -> tuple[str, ...]:
    installs = store.list_managed_installs()
    ordered = sorted(
        installs,
        key=lambda item: (
            1 if bool(item.get("active")) else 0,
            str(item.get("updated_at") or ""),
        ),
        reverse=True,
    )
    candidates: list[str] = []
    seen: set[str] = set()
    for install in ordered:
        workspace = install.get("workspace")
        if not isinstance(workspace, str):
            continue
        normalized = workspace.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)
    return tuple(candidates)


def _managed_workspace_audit_candidates(
    store: _api.Any,
    *,
    workspace_dir: _api.Path | None = None,
) -> tuple[_api.Path, ...]:
    candidates: list[_api.Path] = []
    seen: set[str] = set()
    raw_candidates: list[_api.Path] = []
    if workspace_dir is not None:
        raw_candidates.append(workspace_dir)
    raw_candidates.extend(_api.Path(entry).expanduser() for entry in _api.managed_install_audit_workspace_dirs(store))
    for candidate in raw_candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        normalized = str(resolved)
        if normalized in seen or not resolved.exists() or not resolved.is_dir():
            continue
        if not _api._workspace_has_project_markers(resolved):
            continue
        seen.add(normalized)
        candidates.append(resolved)
    return tuple(candidates)


def resolve_supply_chain_audit_workspace_dir(
    *,
    workspace_dir_value: object,
    workspace_value: object,
    allowed_roots: tuple[_api.Path, ...],
    managed_workspace_dirs: _api.Sequence[str] | None = None,
) -> _api.Path | None:
    for candidate in (workspace_dir_value, workspace_value):
        if isinstance(candidate, str):
            resolved = _api.resolve_path_within_allowed_roots(
                candidate,
                allowed_roots,
                require_exists=True,
            )
            if resolved is not None:
                return resolved
    cursor_project = _api.os.environ.get("CURSOR_PROJECT_DIR", "").strip()
    if cursor_project:
        resolved = _api.resolve_path_within_allowed_roots(
            cursor_project,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None and _api._workspace_has_project_markers(resolved):
            return resolved
    try:
        cwd = _api.Path.cwd().resolve()
    except OSError:
        cwd = None
    if cwd is not None and _api._workspace_has_project_markers(cwd):
        for root in allowed_roots:
            if _api.resolves_within_root(root, cwd, require_exists=True):
                return cwd
    for managed_workspace in managed_workspace_dirs or ():
        resolved = _api.resolve_path_within_allowed_roots(
            managed_workspace,
            allowed_roots,
            require_exists=True,
        )
        if resolved is not None and _api._workspace_has_project_markers(resolved):
            return resolved
    return None


def _audit_lockfile_warnings(
    workspace_dir: _api.Path,
    lockfile_paths: tuple[str, ...],
) -> tuple[dict[str, object], ...]:
    warnings: list[dict[str, object]] = []
    for lockfile_path in lockfile_paths:
        lockfile_name = _api.Path(lockfile_path).name
        disk_path = workspace_dir / lockfile_path
        if not disk_path.exists():
            continue
        if lockfile_name in _api._KNOWN_UNSUPPORTED_LOCKFILE_BASENAMES:
            warnings.append(
                {
                    "code": "bun_lockfile_binary_fallback",
                    "message": (
                        "Guard detected bun.lockb but Bun stores it as a binary lockfile, so audit "
                        "fell back to manifest-only monitoring."
                    ),
                    "path": lockfile_path,
                }
            )
            continue
        if lockfile_name not in _api._ECOSYSTEM_BY_LOCKFILE:
            continue
        lockfile_text = _api._read_workspace_audit_text(workspace_dir, lockfile_path)
        if lockfile_text is None:
            warnings.append(
                {
                    "code": "lockfile_unreadable",
                    "message": f"Guard could not read {lockfile_name} for workspace audit.",
                    "path": lockfile_path,
                }
            )
            continue
        dependency_map = _api.parse_manifest_dependencies(path=lockfile_path, text=lockfile_text)
        if not dependency_map:
            warnings.append(
                {
                    "code": "lockfile_parse_warning",
                    "message": f"Guard could not parse {lockfile_name} for workspace audit.",
                    "path": lockfile_path,
                }
            )
    return tuple(warnings)


def _discover_workspace_audit_paths(workspace_dir: _api.Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    workspace_root = workspace_dir.expanduser().resolve()
    manifests: list[str] = []
    lockfiles: list[str] = []
    for dirpath, dirnames, filenames in _api.os.walk(workspace_root, topdown=True):
        current = _api.Path(dirpath)
        try:
            depth = len(current.relative_to(workspace_root).parts)
        except ValueError:
            continue
        if depth >= _api._WORKSPACE_AUDIT_DISCOVERY_MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = [name for name in dirnames if name not in _api._WORKSPACE_AUDIT_DISCOVERY_SKIP_DIRS]
        for filename in filenames:
            relative = (current / filename).relative_to(workspace_root).as_posix()
            if filename in _api._MANIFEST_CANDIDATE_SET and relative not in manifests:
                manifests.append(relative)
            elif filename in _api._LOCKFILE_CANDIDATE_SET and relative not in lockfiles:
                lockfiles.append(relative)
    return tuple(manifests), tuple(lockfiles)


def _workspace_files(workspace_dir: _api.Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    discovered = _api._discover_workspace_audit_paths(workspace_dir)
    if discovered[0] or discovered[1]:
        return discovered
    return (
        _api.existing_relative_paths(workspace_dir, _api._MANIFEST_CANDIDATES),
        _api.existing_relative_paths(workspace_dir, _api._LOCKFILE_CANDIDATES),
    )


def _target_from_manifest_dependency(ecosystem: str, package_name: str, version: str) -> _api.PackageIntentTarget:
    clean_name = package_name.strip()
    clean_version = version.strip()
    if ecosystem == "npm":
        spec = clean_name if not clean_version else f"{clean_name}@{clean_version}"
        return _api.js_target(spec)
    if ecosystem == "pypi":
        spec = clean_name if not clean_version else f"{clean_name}{clean_version}"
        return _api.python_target(spec)
    if ecosystem == "maven":
        spec = clean_name if not clean_version else f"{clean_name}:{clean_version}"
        return _api.coordinate_target(ecosystem, spec)
    if ecosystem == "packagist":
        spec = clean_name if not clean_version else f"{clean_name}:{clean_version}"
        return _api.composer_target(spec)
    spec = clean_name if not clean_version else f"{clean_name}@{clean_version}"
    return _api.version_target(ecosystem, spec)


def _target_for_package_spec(ecosystem: str, package_spec: str) -> _api.PackageIntentTarget:
    if ecosystem == "npm":
        return _api.js_target(package_spec)
    if ecosystem == "pypi":
        return _api.python_target(package_spec)
    if ecosystem == "maven":
        return _api.coordinate_target(ecosystem, package_spec)
    if ecosystem == "packagist":
        return _api.composer_target(package_spec)
    return _api.version_target(ecosystem, package_spec)


def _package_manager_for_scan(manifest_paths: _api.Sequence[str]) -> str:
    for manifest_path in manifest_paths:
        ecosystem = _api._ECOSYSTEM_BY_MANIFEST.get(_api.Path(manifest_path).name)
        if ecosystem is not None:
            return _api._PACKAGE_MANAGER_BY_ECOSYSTEM.get(ecosystem, ecosystem)
    return "workspace"


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
