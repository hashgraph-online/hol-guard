"""Bounded JavaScript manifest and lockfile parsers with live façade dependencies."""

from __future__ import annotations


def _json_dependency_map(text: str, sections: tuple[str, ...], deadline: float) -> dict[str, str]:
    from . import package_manifest_diff as _api

    _api._ensure_within_deadline(deadline)
    payload = _api.json.loads(text or "{}")
    dependencies: dict[str, str] = {}
    for section in sections:
        values = payload.get(section)
        if isinstance(values, dict):
            for package_name, version in values.items():
                if isinstance(version, str):
                    dependencies[str(package_name)] = version
    return dependencies


def _package_lock_dependency_map(
    text: str, deadline: float, *, document: dict[str, object] | None = None
) -> dict[str, str]:
    from . import package_manifest_diff as _api

    payload = _api.json.loads(text or "{}") if document is None else document
    dependencies: dict[str, str] = {}
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, value in packages.items():
            _api._ensure_within_deadline(deadline)
            if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
                continue
            version = value.get("version") if isinstance(value, dict) else None
            if isinstance(version, str):
                dependencies[package_path.removeprefix("node_modules/")] = version
    if dependencies:
        return dependencies
    legacy_dependencies = payload.get("dependencies")
    if isinstance(legacy_dependencies, dict):
        _api._walk_package_lock_v1_dependencies(legacy_dependencies, dependencies, deadline)
    return dependencies


def _walk_package_lock_v1_dependencies(
    payload: dict[str, object],
    dependencies: dict[str, str],
    deadline: float,
) -> None:
    from . import package_manifest_diff as _api

    for package_name, value in payload.items():
        _api._ensure_within_deadline(deadline)
        if not isinstance(package_name, str) or not isinstance(value, dict):
            continue
        version = value.get("version")
        if isinstance(version, str):
            dependencies[package_name] = version
        nested_dependencies = value.get("dependencies")
        if isinstance(nested_dependencies, dict):
            _api._walk_package_lock_v1_dependencies(nested_dependencies, dependencies, deadline)


def _pnpm_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    from . import package_manifest_diff as _api

    dependencies: dict[str, str] = {}
    package_versions: dict[str, str] = {}
    section: str | None = None
    dependency_block = False
    for raw_line in text.splitlines():
        _api._ensure_within_deadline(deadline)
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            section = stripped.removesuffix(":")
            dependency_block = False
            continue
        if section not in {"packages", "snapshots"}:
            continue
        if indent == 2 and stripped.endswith(":"):
            dependency_block = False
            entry_name, entry_version = _api._pnpm_entry_name_version(stripped[:-1].strip().strip('"').strip("'"))
            if entry_name is not None and entry_version is not None:
                package_versions[entry_name] = entry_version
                dependencies[entry_name] = entry_version
            continue
        if section == "snapshots" and indent == 4 and stripped == "dependencies:":
            dependency_block = True
            continue
        if section == "snapshots" and indent <= 4:
            dependency_block = False
        if not dependency_block or indent < 6 or ":" not in stripped:
            continue
        dependency_name, _, dependency_value = stripped.partition(":")
        normalized_name = dependency_name.strip().strip('"').strip("'")
        normalized_value = dependency_value.strip().strip('"').strip("'")
        exact_version = package_versions.get(normalized_name) or _api._exact_dependency_version(normalized_value)
        if exact_version is not None:
            dependencies[normalized_name] = exact_version
    return dependencies


def _pnpm_entry_name_version(entry: str) -> tuple[str | None, str | None]:
    normalized_entry = entry.split("(", 1)[0].lstrip("/")
    if "@" not in normalized_entry:
        return None, None
    package_name, _, package_version = normalized_entry.rpartition("@")
    if not package_name or not package_version:
        return None, None
    return package_name, package_version


def _yarn_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    from . import package_manifest_diff as _api

    dependencies: dict[str, str] = {}
    current_names: tuple[str, ...] = ()
    for raw_line in text.splitlines():
        _api._ensure_within_deadline(deadline)
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")):
            current_names = _api._yarn_selector_names(stripped.removesuffix(":"))
            continue
        if not current_names:
            continue
        version_match = _api._YARN_CLASSIC_VERSION_RE.match(stripped) or _api._YARN_BERRY_VERSION_RE.match(stripped)
        if version_match is None:
            continue
        version = version_match.group(1)
        for package_name in current_names:
            dependencies[package_name] = version
    return dependencies


def _yarn_selector_names(selector_line: str) -> tuple[str, ...]:
    from . import package_manifest_diff as _api

    names: list[str] = []
    for part in selector_line.split(","):
        selector = part.strip().strip('"').strip("'")
        if not selector or selector == "__metadata":
            continue
        package_name = _api._yarn_selector_name(selector)
        if package_name and package_name not in names:
            names.append(package_name)
    return tuple(names)


def _yarn_selector_name(selector: str) -> str | None:
    if "@npm:" in selector and not selector.startswith("@npm:"):
        return selector.partition("@npm:")[0] or None
    if selector.startswith("@"):
        package_name, _, _ = selector.rpartition("@")
        return package_name or selector
    package_name, _, _ = selector.partition("@")
    return package_name or selector


def _bun_lock_dependency_map(
    text: str, deadline: float, *, document: dict[str, object] | None = None
) -> dict[str, str]:
    from . import package_manifest_diff as _api

    versions_by_name = _api._bun_lock_package_versions(text, deadline, document=document)
    dependencies: dict[str, str] = {}
    for package_name, versions in versions_by_name.items():
        if versions:
            dependencies[package_name] = versions[0]
    return dependencies


def _bun_lock_package_versions(
    text: str, deadline: float, *, document: dict[str, object] | None = None
) -> dict[str, list[str]]:
    from . import package_manifest_diff as _api

    _api._ensure_within_deadline(deadline)
    payload = (
        _api.loads_jsonc(text or "{}", deadline_check=lambda: _api._ensure_within_deadline(deadline))
        if document is None
        else document
    )
    if not isinstance(payload, dict):
        raise ValueError("unsupported Bun lockfile shape")
    packages = payload.get("packages", {})
    if not isinstance(packages, dict):
        raise ValueError("unsupported Bun packages shape")
    versions_by_name: dict[str, list[str]] = {}
    for package in packages.values():
        _api._ensure_within_deadline(deadline)
        if not isinstance(package, list) or not package or not isinstance(package[0], str):
            raise ValueError("unsupported Bun package entry")
        identity = _api._bun_resolution_identity(package[0])
        if identity is None:
            continue
        package_name, version = identity
        versions = versions_by_name.setdefault(package_name, [])
        if version not in versions:
            versions.append(version)
    return versions_by_name


def _bun_resolution_identity(resolution: str) -> tuple[str, str] | None:
    if resolution.startswith("@"):
        scope_separator = resolution.find("/")
        version_separator = resolution.find("@", scope_separator + 1)
    else:
        version_separator = resolution.find("@")
    if version_separator <= 0:
        return None
    package_name = resolution[:version_separator]
    version = resolution[version_separator + 1 :]
    if version.startswith("npm:"):
        version = version.removeprefix("npm:")
    if (
        not package_name
        or not version
        or version.startswith(("workspace:", "root:", "file:", "link:", "git:", "git+", "http:", "https:"))
    ):
        return None
    return package_name, version


def _exact_dependency_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().strip('"').strip("'")
    if not normalized:
        return None
    while normalized.startswith(("=", "^", "~", "v")):
        normalized = normalized[1:]
    return normalized or None
