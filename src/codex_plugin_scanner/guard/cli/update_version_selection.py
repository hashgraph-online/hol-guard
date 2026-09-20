"""Bounded release metadata and Python compatibility selection."""

from __future__ import annotations

from collections.abc import Mapping

from ..mdm.contracts import ManagedNetworkPolicy


def _version_check_payload(
    current_version: str,
    *,
    source_kind: str = "pypi",
    network_policy: ManagedNetworkPolicy | None = None,
    include_alpha: bool = False,
) -> dict[str, object]:
    if source_kind != "pypi":
        return {
            "source": source_kind,
            "status": "source_managed",
            "current_version": current_version,
            "latest_version": None,
            "update_available": None,
        }
    policy_token = _update._version_network_policy.set(network_policy)
    try:
        latest_version = (
            _update._latest_alpha_version_from_pypi(current_version)
            if include_alpha
            else _update._latest_version_from_pypi()
        )
    finally:
        _update._version_network_policy.reset(policy_token)
    if latest_version is None:
        return {
            "source": "pypi",
            "status": "unavailable",
            "current_version": current_version,
            "latest_version": None,
            "update_available": None,
        }
    update_available = _update._is_newer_version(latest_version, current_version)
    if update_available is None:
        return {
            "source": "pypi",
            "status": "unavailable",
            "current_version": current_version,
            "latest_version": latest_version,
            "update_available": None,
        }
    required_python_requirements = _update._latest_version_python_requirements(latest_version)
    runtime_python = _update._runtime_python_version()
    if update_available and not _update._python_requirements_satisfied(required_python_requirements, runtime_python):
        compatible_version = _update._latest_compatible_release_version(
            current_version,
            runtime_python,
            include_alpha=include_alpha,
        )
        if compatible_version is not None:
            return {
                "source": "pypi",
                **({"release_channel": "alpha"} if include_alpha else {}),
                "status": "stale",
                "current_version": current_version,
                "latest_version": compatible_version,
                "update_available": True,
                "pypi_latest_version": latest_version,
                "pypi_latest_python_incompatible": True,
                "pypi_latest_required_python": _update._format_python_requirements(required_python_requirements),
                "runtime_python": runtime_python,
            }
        return {
            "source": "pypi",
            **({"release_channel": "alpha"} if include_alpha else {}),
            "status": "python_incompatible",
            "current_version": current_version,
            "latest_version": latest_version,
            "update_available": True,
            "required_python": _update._format_python_requirements(required_python_requirements),
            "runtime_python": runtime_python,
        }
    published_alpha = _update.newest_pypi_version(_update._last_pypi_payload, include_stable=False, include_alpha=True)
    reserved_alpha = _update._newest_reserved_alpha_version(latest_pypi=published_alpha) if include_alpha else None
    return {
        "source": "pypi",
        **({"release_channel": "alpha"} if include_alpha else {}),
        "status": "stale" if update_available else "current",
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": update_available,
        **({"reserved_alpha_version": reserved_alpha} if reserved_alpha else {}),
    }


def _latest_version_from_pypi() -> str | None:
    request = _update.urllib.request.Request(_update._PYPI_JSON_URL, headers={"Accept": "application/json"})
    deadline = _update.time.monotonic() + _update._PYPI_TIMEOUT_SECONDS
    try:
        with _update.managed_urlopen(
            request,
            timeout=_update._PYPI_TIMEOUT_SECONDS,
            policy=_update._version_network_policy.get(),
        ) as response:
            raw_payload = _update._read_bounded_pypi_response(response, deadline=deadline)
            if len(raw_payload) > _update._PYPI_RESPONSE_LIMIT_BYTES:
                return None
            payload = _update.json.loads(raw_payload.decode("utf-8"))
    except (
        _update.ManagedNetworkError,
        OSError,
        TimeoutError,
        _update.urllib.error.URLError,
        _update.http.client.IncompleteRead,
        _update.json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None
    if not isinstance(payload, dict):
        return None
    _update._last_pypi_payload = payload
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    return version if isinstance(version, str) and version.strip() else None


def _latest_alpha_version_from_pypi(current_version: str) -> str | None:
    """Return the newest non-yanked stable or alpha release on PyPI."""
    _ = current_version
    _ = _update._latest_version_from_pypi()
    return _update.newest_pypi_version(_update._last_pypi_payload, include_stable=True, include_alpha=True)


def already_current_update_message(version_check: Mapping[str, object] | None) -> str:
    if not version_check:
        return "HOL Guard is already current."
    latest = version_check.get("latest_version")
    reserved = version_check.get("reserved_alpha_version")
    if (
        isinstance(latest, str)
        and latest.strip()
        and isinstance(reserved, str)
        and reserved.strip()
        and _update._is_newer_version(reserved.strip(), latest.strip()) is True
    ):
        return (
            f"HOL Guard is already current on PyPI ({latest.strip()}). "
            f"GitHub reserved {reserved.strip()}, but that alpha is not published yet."
        )
    return "HOL Guard is already current."


def select_reserved_alpha_version(refs: object, *, latest_pypi: str | None) -> str | None:
    """Return the newest reserved alpha on the same series as the live PyPI alpha."""

    if not isinstance(refs, list):
        return None
    latest_base: str | None = None
    latest_text = latest_pypi.strip() if isinstance(latest_pypi, str) else ""
    if latest_text:
        try:
            latest_base = _update.Version(latest_text).base_version
        except _update.InvalidVersion:
            latest_base = None
    candidates: list[tuple[_update.Version, str]] = []
    for item in refs:
        if not isinstance(item, dict):
            continue
        ref = item.get("ref")
        if not isinstance(ref, str) or not ref.startswith("refs/tags/alpha/v"):
            continue
        version_text = ref.removeprefix("refs/tags/alpha/v")
        try:
            parsed_version = _update.Version(version_text)
        except _update.InvalidVersion:
            continue
        if parsed_version.pre is None or parsed_version.pre[0] != "a":
            continue
        if latest_base is not None and parsed_version.base_version != latest_base:
            continue
        candidates.append((parsed_version, version_text))
    if not candidates:
        return None
    newest = max(candidates, key=lambda candidate: candidate[0])[1]
    if latest_text and _update._is_newer_version(newest, latest_text) is not True:
        return None
    return newest


def _newest_reserved_alpha_version(*, latest_pypi: str | None) -> str | None:
    request = _update.urllib.request.Request(
        _update._GITHUB_ALPHA_REFS_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "hol-guard-update",
        },
    )
    deadline = _update.time.monotonic() + _update._PYPI_TIMEOUT_SECONDS
    try:
        with _update.managed_urlopen(
            request,
            timeout=_update._PYPI_TIMEOUT_SECONDS,
            policy=_update._version_network_policy.get(),
        ) as response:
            raw_payload = _update._read_bounded_pypi_response(response, deadline=deadline)
            payload = _update.json.loads(raw_payload.decode("utf-8"))
    except (
        _update.ManagedNetworkError,
        OSError,
        TimeoutError,
        _update.urllib.error.URLError,
        _update.http.client.IncompleteRead,
        _update.json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None
    return _update.select_reserved_alpha_version(payload, latest_pypi=latest_pypi)


def _read_bounded_pypi_response(response: object, *, deadline: float) -> bytes:
    read = getattr(response, "read1", None)
    if not callable(read):
        read = getattr(response, "read", None)
        if not callable(read):
            raise OSError("PyPI response is not readable")
        if _update.time.monotonic() >= deadline:
            raise TimeoutError("PyPI response deadline exceeded")
        payload = read(_update._PYPI_RESPONSE_LIMIT_BYTES + 1)
        if _update.time.monotonic() >= deadline:
            raise TimeoutError("PyPI response deadline exceeded")
        if not isinstance(payload, bytes):
            raise OSError("PyPI response returned non-byte content")
        return payload
    payload = bytearray()
    while True:
        if _update.time.monotonic() >= deadline:
            raise TimeoutError("PyPI response deadline exceeded")
        remaining_capacity = _update._PYPI_RESPONSE_LIMIT_BYTES + 1 - len(payload)
        if remaining_capacity <= 0:
            return bytes(payload)
        chunk = read(min(_update._PYPI_READ_CHUNK_BYTES, remaining_capacity))
        if not isinstance(chunk, bytes):
            raise OSError("PyPI response returned non-byte content")
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > _update._PYPI_RESPONSE_LIMIT_BYTES:
            return bytes(payload)


def _latest_compatible_release_version(
    current_version: str,
    runtime_python: str,
    *,
    include_alpha: bool = False,
) -> str | None:
    payload = _update._last_pypi_payload
    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return None
    candidates: list[tuple[_update.Version, str]] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not version_text.strip():
            continue
        try:
            parsed_version = _update.Version(version_text)
        except _update.InvalidVersion:
            continue
        if parsed_version.is_prerelease and (
            not include_alpha or parsed_version.pre is None or parsed_version.pre[0] != "a"
        ):
            continue
        if _update._is_newer_version(version_text, current_version) is not True:
            continue
        if not _update._release_has_non_yanked_file(files):
            continue
        requirements = _update._latest_version_python_requirements(version_text)
        if _update._python_requirements_satisfied(requirements, runtime_python):
            candidates.append((parsed_version, version_text.strip()))
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate[0])[1]


def _release_has_non_yanked_file(files: object) -> bool:
    if not isinstance(files, list):
        return False
    return any(isinstance(file_payload, dict) and not file_payload.get("yanked") for file_payload in files)


def _runtime_python_version() -> str:
    return _update.platform.python_version()


def _latest_version_python_requirements(latest_version: str) -> tuple[str, ...] | None:
    payload = _update._last_pypi_payload
    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if isinstance(releases, dict):
        files = releases.get(latest_version)
        if isinstance(files, list):
            requirements: list[str] = []
            for file_payload in files:
                if not isinstance(file_payload, dict) or file_payload.get("yanked"):
                    continue
                requires_python = file_payload.get("requires_python")
                if not isinstance(requires_python, str) or not requires_python.strip():
                    continue
                requirement = requires_python.strip()
                if requirement not in requirements:
                    requirements.append(requirement)
            if requirements:
                return tuple(requirements)
    info = payload.get("info")
    if isinstance(info, dict) and info.get("version") == latest_version:
        requires_python = info.get("requires_python")
        if isinstance(requires_python, str) and requires_python.strip():
            return (requires_python.strip(),)
    return None


def _python_requirements_satisfied(requirements: tuple[str, ...] | None, runtime_python: str) -> bool:
    if not requirements:
        return True
    for requires_python in requirements:
        try:
            if _update.SpecifierSet(requires_python).contains(runtime_python, prereleases=True):
                return True
        except _update.InvalidSpecifier:
            return True
    return False


def _format_python_requirements(requirements: tuple[str, ...] | None) -> str | None:
    if not requirements:
        return None
    return " or ".join(requirements)


def _python_runtime_blocks_update(version_check: object) -> bool:
    return isinstance(version_check, dict) and version_check.get("status") == "python_incompatible"


def _python_runtime_block_message(version_check: object) -> str:
    if not isinstance(version_check, dict):
        return "HOL Guard update requires a different Python runtime."
    latest_version = version_check.get("latest_version")
    required_python = version_check.get("required_python")
    runtime_python = version_check.get("runtime_python")
    latest_label = (
        latest_version if isinstance(latest_version, str) and latest_version.strip() else "the latest release"
    )
    requirement_label = (
        required_python
        if isinstance(required_python, str) and required_python.strip()
        else "the supported Python range"
    )
    runtime_label = runtime_python if isinstance(runtime_python, str) and runtime_python.strip() else "this Python"
    return (
        f"HOL Guard {latest_label} requires Python {requirement_label}; this install is running Python "
        f"{runtime_label}. Reinstall HOL Guard with Python {requirement_label} (for example, Python 3.13 when "
        "the latest release requires <3.14), then rerun hol-guard update."
    )


def _is_newer_version(latest_version: str, current_version: str) -> bool | None:
    try:
        latest = _update.Version(latest_version)
        current = _update.Version(current_version)
    except _update.InvalidVersion:
        return None
    return latest > current


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
