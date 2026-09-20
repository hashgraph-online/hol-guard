"""Registry version resolution and package selectors."""

from __future__ import annotations


def _resolved_target_version(
    *,
    target: dict[str, object],
    lockfile_versions: dict[tuple[str, str | None], str],
) -> str | None:
    exact_version = _eval._optional_string(target.get("version"))
    if exact_version is not None:
        return exact_version
    lockfile_version = lockfile_versions.get(_eval._lockfile_target_key(target))
    if lockfile_version is not None:
        return lockfile_version
    requested_range = _eval._optional_string(target.get("range"))
    if requested_range is None:
        return None
    exact_version = _eval._exact_version(requested_range)
    if exact_version is not None:
        return exact_version
    registry_version = _eval._registry_resolved_target_version(target=target, requested_range=requested_range)
    if registry_version is not None:
        return registry_version
    return None


def _registry_resolved_target_version(*, target: dict[str, object], requested_range: str) -> str | None:
    ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
    if _eval._optional_string(target.get("source_url")) is not None:
        return None
    package_name = _eval._registry_package_name(target)
    if package_name is None:
        return None
    if ecosystem == "npm":
        return _eval._npm_registry_resolved_version(package_name=package_name, requested_range=requested_range)
    if ecosystem == "pypi":
        normalized_name = _eval._normalize_package_name("pypi", package_name)
        return _eval._pypi_registry_resolved_version(package_name=normalized_name, requested_range=requested_range)
    return None


def _registry_package_name(target: dict[str, object]) -> str | None:
    package_name = _eval._optional_string(target.get("name"))
    if package_name is None:
        return None
    namespace = _eval._optional_string(target.get("namespace"))
    return f"{namespace}/{package_name}" if namespace is not None else package_name


def _npm_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = (
        f"{_eval._NPM_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{_eval.urllib.parse.quote(package_name, safe='')}"
    )
    request = _eval.urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/vnd.npm.install-v1+json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _eval._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_eval._TIMEOUT_SECONDS,
            retry_timeout_seconds=_eval._RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    versions_payload = payload.get("versions")
    if not isinstance(versions_payload, dict):
        return None
    versions = [version for version in versions_payload if isinstance(version, str)]
    if not versions:
        return None
    return _eval.highest_js_version_for_selector(versions, requested_range)


def _pypi_registry_resolved_version(*, package_name: str, requested_range: str) -> str | None:
    metadata_url = (
        f"{_eval._PYPI_REGISTRY_METADATA_BASE_URL.rstrip('/')}/{_eval.urllib.parse.quote(package_name, safe='')}/json"
    )
    request = _eval.urllib.request.Request(
        metadata_url,
        headers={
            "Accept": "application/json",
            "User-Agent": "hol-guard-local",
        },
    )
    try:
        payload = _eval._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_eval._TIMEOUT_SECONDS,
            retry_timeout_seconds=_eval._RETRY_TIMEOUT_SECONDS,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    releases_payload = payload.get("releases")
    if not isinstance(releases_payload, dict):
        return None
    normalized_range = _eval._normalized_pypi_requested_range(requested_range)
    if normalized_range is None:
        return None
    try:
        specifier = _eval.SpecifierSet(normalized_range)
    except _eval.InvalidSpecifier:
        return None
    matching_versions: list[_eval.Version] = []
    for release in releases_payload:
        if not isinstance(release, str):
            continue
        try:
            parsed_version = _eval.Version(release)
        except _eval.InvalidVersion:
            continue
        if parsed_version in specifier:
            matching_versions.append(parsed_version)
    if not matching_versions:
        return None
    matching_versions.sort()
    return str(matching_versions[-1])


def _normalized_pypi_requested_range(requested_range: str) -> str | None:
    normalized = requested_range.strip()
    if not normalized:
        return None
    if normalized.startswith("~="):
        return normalized
    if normalized.startswith("^"):
        return _eval._pypi_caret_specifier(normalized[1:])
    if normalized.startswith("~"):
        return _eval._pypi_tilde_specifier(normalized[1:])
    return normalized


def _pypi_caret_specifier(value: str) -> str | None:
    base = _eval._optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = _eval.Version(base)
    except _eval.InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    minor = release[1] if len(release) >= 2 else 0
    patch = release[2] if len(release) >= 3 else 0
    if major > 0:
        upper_bound = f"{major + 1}"
    elif minor > 0:
        upper_bound = f"0.{minor + 1}"
    else:
        upper_bound = f"0.0.{patch + 1}"
    return f">={base},<{upper_bound}"


def _pypi_tilde_specifier(value: str) -> str | None:
    base = _eval._optional_string(value)
    if base is None:
        return None
    try:
        parsed_version = _eval.Version(base)
    except _eval.InvalidVersion:
        return None
    release = parsed_version.release
    major = release[0] if len(release) >= 1 else 0
    upper_bound = f"{major}.{release[1] + 1}" if len(release) >= 2 else f"{major + 1}"
    return f">={base},<{upper_bound}"


def _manifest_exact_version(ecosystem: str, value: str | None) -> str | None:
    if ecosystem == "pypi":
        return _eval._python_lockfile_version(value)
    if ecosystem == "cargo":
        normalized = _eval._optional_string(value)
        if normalized is None:
            return None
        if normalized.startswith("="):
            return _eval._exact_version(normalized.lstrip("="))
        return None
    return _eval._exact_version(value)


def _split_namespace_name(value: str, *, ecosystem: str) -> tuple[str | None, str]:
    try:
        identity = _eval.parse_package_identity(ecosystem=ecosystem, package_name=value, version="*")
    except _eval.PackageIdentityError:
        return None, value
    return identity.namespace, identity.name


def _npm_source_spec(value: str | None, *, ecosystem: str) -> _eval.NpmSourceSpec | None:
    return _eval.parse_npm_source_spec(value) if ecosystem.lower() == "npm" else None


def _default_registry_range(ecosystem: str) -> str | None:
    return _eval._REGISTRY_DEFAULT_RANGES.get(ecosystem)


def _requested_specifier_is_range(value: str | None, *, ecosystem: str) -> bool:
    normalized = _eval._optional_string(value)
    if normalized is None:
        return False
    if _eval._exact_version(normalized) is None:
        return True
    if ecosystem not in _eval._DIST_TAG_RANGE_ECOSYSTEMS:
        return False
    return _eval.re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", normalized) is not None


def _target_candidate_names(target: dict[str, object]) -> tuple[str, ...]:
    alias = _eval._optional_string(target.get("alias"))
    namespace = _eval._optional_string(target.get("namespace"))
    ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
    name = str(target["name"])
    candidates: list[str] = []
    if alias is not None:
        candidates.append(alias)
    qualified_name = f"{namespace}/{name}" if namespace is not None else name
    candidates.append(qualified_name)
    normalized_name = _eval._normalize_package_name(ecosystem, qualified_name)
    if normalized_name not in candidates:
        candidates.append(normalized_name)
    raw_package_name = _eval._optional_string(target.get("package_name"))
    if raw_package_name is not None and raw_package_name not in candidates:
        candidates.append(raw_package_name)
        raw_normalized = _eval._normalize_package_name(ecosystem, raw_package_name)
        if raw_normalized not in candidates:
            candidates.append(raw_normalized)
    return tuple(candidates)


def _python_lockfile_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().strip('"').strip("'")
    if ";" in normalized:
        normalized = normalized.split(";", 1)[0].strip()
    if normalized.startswith(("==", "===")):
        normalized = normalized.lstrip("=")
    if not normalized:
        return None
    try:
        _eval.Version(normalized)
    except _eval.InvalidVersion:
        return None
    return normalized


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
