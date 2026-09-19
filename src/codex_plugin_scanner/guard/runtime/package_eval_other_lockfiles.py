"""Non-npm lockfile version selection."""

from __future__ import annotations


def _cargo_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    parse_result = _eval._safe_dependency_map_result_for_path("Cargo.lock", text, deadline=_eval.time.monotonic() + 0.2)
    return _eval._target_versions_from_direct_map(targets, parse_result.dependency_map())


def _composer_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    parse_result = _eval._safe_dependency_map_result_for_path(
        "composer.lock",
        text,
        deadline=_eval.time.monotonic() + 0.2,
    )
    return _eval._target_versions_from_direct_map(targets, parse_result.dependency_map())


def _gemfile_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    parse_result = _eval._safe_dependency_map_result_for_path(
        "Gemfile.lock",
        text,
        deadline=_eval.time.monotonic() + 0.2,
    )
    return _eval._target_versions_from_direct_map(targets, parse_result.dependency_map())


def _pnpm_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    direct_versions: dict[str, str] = {}
    section: str | None = None
    importer: str | None = None
    dependency_block: str | None = None
    dependency_name: str | None = None
    top_level_dependency_sections = {"dependencies", "devDependencies", "optionalDependencies"}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            section = stripped.removesuffix(":")
            importer = None
            dependency_block = None
            dependency_name = None
            continue
        if section in top_level_dependency_sections:
            if indent == 2 and ":" in stripped:
                raw_name, _, raw_value = stripped.partition(":")
                dependency_name = raw_name.strip().strip('"').strip("'")
                direct_value = raw_value.strip().strip('"').strip("'")
                exact_version = _eval._direct_lockfile_version(direct_value)
                if exact_version is not None:
                    direct_versions[dependency_name] = exact_version
                    dependency_name = None
                continue
            if dependency_name is not None and indent >= 4 and stripped.startswith("version:"):
                exact_version = _eval._direct_lockfile_version(stripped.partition(":")[2].strip().strip('"').strip("'"))
                if exact_version is not None:
                    direct_versions[dependency_name] = exact_version
                dependency_name = None
            continue
        if section != "importers":
            continue
        if indent == 2 and stripped.endswith(":"):
            importer = stripped[:-1].strip('"').strip("'")
            dependency_block = None
            dependency_name = None
            continue
        if importer not in {".", "default"}:
            continue
        if indent == 4 and stripped.endswith(":"):
            block_name = stripped.removesuffix(":")
            dependency_block = block_name if "dependencies" in block_name.lower() else None
            dependency_name = None
            continue
        if dependency_block is None:
            continue
        if indent == 6 and ":" in stripped:
            raw_name, _, raw_value = stripped.partition(":")
            dependency_name = raw_name.strip().strip('"').strip("'")
            direct_value = raw_value.strip().strip('"').strip("'")
            exact_version = _eval._direct_lockfile_version(direct_value)
            if exact_version is not None:
                direct_versions[dependency_name] = exact_version
                dependency_name = None
            continue
        if dependency_name is not None and indent >= 8 and stripped.startswith("version:"):
            exact_version = _eval._direct_lockfile_version(stripped.partition(":")[2].strip().strip('"').strip("'"))
            if exact_version is not None:
                direct_versions[dependency_name] = exact_version
            dependency_name = None
    return _eval._target_versions_from_direct_map(targets, direct_versions)


def _yarn_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    versions: dict[tuple[str, str | None], str] = {}
    current_selectors: tuple[str, ...] = ()
    target_selectors = {
        _eval._lockfile_target_key(target): set(_eval._expected_yarn_selectors(target)) for target in targets
    }
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")):
            current_selectors = tuple(
                selector
                for selector in (part.strip().strip('"').strip("'") for part in stripped.removesuffix(":").split(","))
                if selector and selector != "__metadata"
            )
            continue
        if not current_selectors:
            continue
        version_match = _eval.re.match(r'^version\s+"([^"]+)"$', stripped) or _eval.re.match(
            r'^version:\s*"?([^"\s]+)"?$',
            stripped,
        )
        if version_match is None:
            continue
        version = version_match.group(1)
        selector_set = set(current_selectors)
        for target_key, expected_selectors in target_selectors.items():
            if target_key in versions or not expected_selectors:
                continue
            if selector_set & expected_selectors:
                versions[target_key] = version
    return versions


def _yarn_lock_target_versions_from_entries(
    parse_result: _eval.LockfileParseResult,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    # A selector's first declaration wins, including when one target has several
    # accepted spellings. Dependency-map projection separately remains last-wins.
    selector_first: dict[str, tuple[int, str]] = {}
    for index, (selectors, version) in enumerate(parse_result.yarn_selector_versions):
        for selector in selectors:
            selector_first.setdefault(selector, (index, version))
    versions: dict[tuple[str, str | None], str] = {}
    target_selectors = {
        _eval._lockfile_target_key(target): _eval._expected_yarn_selectors(target) for target in targets
    }
    for target_key, expected_selectors in target_selectors.items():
        matches = [selector_first[selector] for selector in expected_selectors if selector in selector_first]
        if matches:
            versions[target_key] = min(matches, key=lambda item: item[0])[1]
    return versions


def _expected_yarn_selectors(target: dict[str, object]) -> tuple[str, ...]:
    requested = _eval._optional_string(target.get("version")) or _eval._optional_string(target.get("range"))
    if requested is None:
        return ()
    normalized_name = str(target["normalized_name"])
    alias = _eval._optional_string(target.get("alias"))
    selectors = [f"{normalized_name}@{requested}", f"{normalized_name}@npm:{requested}"]
    if alias is not None:
        selectors.append(f"{alias}@npm:{normalized_name}@{requested}")
    return tuple(dict.fromkeys(selectors))


def _bun_lock_target_versions(
    parse_result: _eval.LockfileParseResult,
    targets: tuple[dict[str, object], ...],
) -> dict[tuple[str, str | None], str]:
    versions_by_name: dict[str, list[str]] = {}
    for entry in parse_result.entries:
        candidate_versions = versions_by_name.setdefault(entry.package_name, [])
        if entry.version not in candidate_versions:
            candidate_versions.append(entry.version)
    versions: dict[tuple[str, str | None], str] = {}
    for target in targets:
        target_key = _eval._lockfile_target_key(target)
        requested = _eval._optional_string(target.get("range"))
        candidates = versions_by_name.get(str(target["normalized_name"]), [])
        if len(candidates) == 1:
            versions[target_key] = candidates[0]
            continue
        if requested is None:
            continue
        matching_versions = [value for value in candidates if _eval.version_matches_js_selector(value, requested)]
        if len(matching_versions) == 1:
            versions[target_key] = matching_versions[0]
    return versions


def _poetry_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
    direct_manifest_names: set[str],
) -> dict[tuple[str, str | None], str]:
    return _eval._target_versions_from_direct_map(
        targets,
        _eval._poetry_lock_direct_versions(text, direct_manifest_names),
    )


def _toml_lock_direct_versions(text: str, direct_manifest_names: set[str]) -> dict[str, str]:
    try:
        payload = _eval.tomllib.loads(text or "")
    except _eval.tomllib.TOMLDecodeError:
        return {}
    packages = payload.get("package")
    direct_versions: dict[str, str] = {}
    if not isinstance(packages, list):
        return direct_versions
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = _eval._optional_string(package.get("name"))
        version = _eval._optional_string(package.get("version"))
        normalized_name = _eval._normalize_package_name("pypi", name) if name is not None else None
        if normalized_name is None or version is None or normalized_name not in direct_manifest_names:
            continue
        direct_versions[normalized_name] = version
    return direct_versions


def _uv_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
    direct_manifest_names: set[str],
) -> dict[tuple[str, str | None], str]:
    return _eval._target_versions_from_direct_map(
        targets,
        _eval._uv_lock_direct_versions(text, direct_manifest_names),
    )


def _pipfile_lock_target_versions(
    text: str,
    targets: tuple[dict[str, object], ...],
    direct_manifest_names: set[str],
) -> dict[tuple[str, str | None], str]:
    return _eval._target_versions_from_direct_map(
        targets,
        _eval._pipfile_lock_direct_versions(text, direct_manifest_names),
    )


def _pipfile_lock_direct_versions(text: str, direct_manifest_names: set[str]) -> dict[str, str]:
    try:
        payload = _eval.json.loads(text or "{}")
    except _eval.json.JSONDecodeError:
        return {}
    direct_versions: dict[str, str] = {}
    for section in ("default", "develop"):
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for package_name, package_value in values.items():
            if not isinstance(package_name, str) or not isinstance(package_value, dict):
                continue
            exact_version = _eval._python_lockfile_version(package_value.get("version"))
            normalized_name = _eval._normalize_package_name("pypi", package_name)
            if exact_version is not None and normalized_name in direct_manifest_names:
                direct_versions[normalized_name] = exact_version
    return direct_versions


def _target_versions_from_direct_map(
    targets: tuple[dict[str, object], ...],
    direct_versions: dict[str, str],
) -> dict[tuple[str, str | None], str]:
    versions: dict[tuple[str, str | None], str] = {}
    for target in targets:
        target_key = _eval._lockfile_target_key(target)
        for candidate in _eval._target_candidate_names(target):
            version = direct_versions.get(candidate)
            if version is not None:
                versions[target_key] = version
                break
    return versions


def _lockfile_target_key(target: dict[str, object]) -> tuple[str, str | None]:
    return str(target["normalized_name"]), _eval._optional_string(target.get("alias"))


def _dependency_package_name(dependency_path: str) -> str | None:
    normalized_dependency_path = dependency_path.strip("/").lower()
    if not normalized_dependency_path:
        return None
    if "node_modules/" in normalized_dependency_path:
        return normalized_dependency_path.rsplit("node_modules/", 1)[-1]
    if "/" not in normalized_dependency_path or normalized_dependency_path.startswith("@"):
        return normalized_dependency_path
    return None


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
