"""Pure release-candidate selection for Guard update channels."""

from __future__ import annotations

from packaging.version import InvalidVersion, Version


def newest_pypi_version(
    payload: object,
    *,
    include_stable: bool,
    include_alpha: bool,
) -> str | None:
    """Return the newest available release admitted by the requested channels."""

    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return None
    candidates: list[tuple[Version, str]] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not version_text.strip() or not _release_is_available(files):
            continue
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue
        if version.is_prerelease:
            if not include_alpha or version.pre is None or version.pre[0] != "a":
                continue
        elif not include_stable:
            continue
        candidates.append((version, version_text.strip()))
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate[0])[1]


def _release_is_available(files: object) -> bool:
    return isinstance(files, list) and any(
        isinstance(file_payload, dict) and not file_payload.get("yanked") for file_payload in files
    )


__all__ = ["newest_pypi_version"]
