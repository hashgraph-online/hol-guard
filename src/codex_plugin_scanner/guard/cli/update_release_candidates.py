"""Pure release-candidate selection for Guard update channels."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from packaging.version import InvalidVersion, Version

MAX_ALPHA_LIVENESS_LOOKUPS = 3


def newest_pypi_version(
    payload: object,
    *,
    include_stable: bool,
    include_alpha: bool,
) -> str | None:
    """Return the newest available release admitted by the requested channels."""

    candidates = _pypi_candidates(payload, include_stable=include_stable, include_alpha=include_alpha)
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: candidate[0])[1]


def _pypi_candidates(
    payload: object,
    *,
    include_stable: bool,
    include_alpha: bool,
) -> list[tuple[Version, str]]:
    if not isinstance(payload, dict):
        return []
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return []
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
    return candidates


def select_live_release(
    candidates: Iterable[tuple[Version, str]],
    *,
    alpha_is_live: Callable[[str], bool],
    max_lookups: int = MAX_ALPHA_LIVENESS_LOOKUPS,
) -> str | None:
    """Return the newest candidate that is stable or a still-published alpha.

    Retracting an alpha deletes its GitHub prerelease and tag, but PyPI keeps the
    upload. Candidates are walked newest first; a stable release is returned
    without any lookup, while an alpha is offered only when ``alpha_is_live``
    confirms it. At most ``max_lookups`` alphas are checked; every alpha beyond
    that budget is skipped so an unverifiable alpha is never offered.
    """

    lookups = 0
    for version, version_text in sorted(candidates, key=lambda candidate: candidate[0], reverse=True):
        if not version.is_prerelease:
            return version_text
        if lookups >= max_lookups:
            continue
        lookups += 1
        if alpha_is_live(version_text):
            return version_text
    return None


def live_release_candidates(
    candidates: Iterable[str],
    *,
    alpha_is_live: Callable[[str], bool],
    max_lookups: int = MAX_ALPHA_LIVENESS_LOOKUPS,
) -> list[str]:
    """Drop alphas that are retracted or unverified, keeping every stable candidate.

    Alphas are checked newest first with at most ``max_lookups`` lookups; alphas
    beyond that budget are dropped rather than offered unverified.
    """

    parsed: list[tuple[Version, str]] = []
    for text in candidates:
        try:
            parsed.append((Version(text.strip()), text.strip()))
        except InvalidVersion:
            continue
    live: list[str] = []
    lookups = 0
    for version, version_text in sorted(parsed, key=lambda candidate: candidate[0], reverse=True):
        if not version.is_prerelease:
            live.append(version_text)
            continue
        if lookups >= max_lookups:
            continue
        lookups += 1
        if alpha_is_live(version_text):
            live.append(version_text)
    return live


def newest_live_pypi_version(
    payload: object,
    *,
    alpha_is_live: Callable[[str], bool],
    max_lookups: int = MAX_ALPHA_LIVENESS_LOOKUPS,
) -> str | None:
    """Return the newest stable release or live alpha admitted by the alpha channel."""

    return select_live_release(
        _pypi_candidates(payload, include_stable=True, include_alpha=True),
        alpha_is_live=alpha_is_live,
        max_lookups=max_lookups,
    )


def _release_is_available(files: object) -> bool:
    return isinstance(files, list) and any(
        isinstance(file_payload, dict) and not file_payload.get("yanked") for file_payload in files
    )


__all__ = [
    "MAX_ALPHA_LIVENESS_LOOKUPS",
    "live_release_candidates",
    "newest_live_pypi_version",
    "newest_pypi_version",
    "select_live_release",
]
