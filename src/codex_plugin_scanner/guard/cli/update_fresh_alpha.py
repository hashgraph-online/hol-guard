"""Confirm a just-published alpha that PyPI's cached project index still omits.

PyPI serves ``/pypi/<project>/json`` from a CDN cache that can lag a new upload
by several minutes, while ``/pypi/<project>/<version>/json`` answers for the new
version at once. When GitHub has reserved an alpha that the project index does
not list yet, the updater asks for that version directly and, if PyPI has
non-yanked files for it, adds them to the project payload so the normal
selection walk can choose it.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from .update_release_candidates import newest_pypi_version

_PYPI_VERSION_JSON_URL = "https://pypi.org/pypi/hol-guard/{version}/json"


def fetch_published_release_files(
    version: str,
    *,
    opener: Callable[[urllib.request.Request], AbstractContextManager[Any]],
    read_bounded: Callable[..., bytes],
    timeout: float,
    network_errors: tuple[type[BaseException], ...] = (),
) -> list[dict[str, object]] | None:
    """Return PyPI's non-empty file list for ``version``, or ``None`` when unconfirmed."""

    url = _PYPI_VERSION_JSON_URL.format(version=urllib.parse.quote(version, safe=""))
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    deadline = time.monotonic() + timeout
    try:
        with opener(request) as response:
            payload = json.loads(read_bounded(response, deadline=deadline).decode("utf-8"))
    except (
        *network_errors,
        OSError,
        TimeoutError,
        urllib.error.URLError,
        http.client.HTTPException,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return None
    return release_files_from_version_payload(payload, version)


def release_files_from_version_payload(payload: object, version: str) -> list[dict[str, object]] | None:
    """Return the file entries of a per-version PyPI payload when it names ``version``."""

    if not isinstance(payload, dict):
        return None
    info = payload.get("info")
    if not isinstance(info, dict) or info.get("version") != version:
        return None
    files = payload.get("urls")
    if not isinstance(files, list):
        return None
    entries = [entry for entry in files if isinstance(entry, dict)]
    if not any(not entry.get("yanked") for entry in entries):
        return None
    return entries


def with_confirmed_release(
    payload: dict[str, object] | None,
    version: str,
    files: list[dict[str, object]],
) -> dict[str, object] | None:
    """Return a copy of the project payload whose ``releases`` include ``version``."""

    if not isinstance(payload, dict):
        return None
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return None
    merged_releases = dict(releases)
    merged_releases[version] = files
    merged = dict(payload)
    merged["releases"] = merged_releases
    return merged


@dataclass(frozen=True)
class ReservedAlphaConfirmation:
    """The version to offer, the payload it came from, and any alpha still unpublished."""

    version: str
    payload: dict[str, object] | None
    reserved_alpha: str | None


def confirm_reserved_alpha(
    payload: dict[str, object] | None,
    latest_version: str,
    *,
    reserved_lookup: Callable[[str | None], str | None],
    opener: Callable[[urllib.request.Request], AbstractContextManager[Any]],
    read_bounded: Callable[..., bytes],
    timeout: float,
    network_errors: tuple[type[BaseException], ...] = (),
) -> ReservedAlphaConfirmation:
    """Offer the GitHub-reserved alpha when PyPI already serves files for it."""

    published_alpha = newest_pypi_version(payload, include_stable=False, include_alpha=True)
    reserved_alpha = reserved_lookup(published_alpha)
    unchanged = ReservedAlphaConfirmation(latest_version, payload, reserved_alpha)
    if reserved_alpha is None or not _is_newer(reserved_alpha, latest_version):
        return unchanged
    files = fetch_published_release_files(
        reserved_alpha,
        opener=opener,
        read_bounded=read_bounded,
        timeout=timeout,
        network_errors=network_errors,
    )
    merged = with_confirmed_release(payload, reserved_alpha, files) if files else None
    if merged is None:
        return unchanged
    return ReservedAlphaConfirmation(reserved_alpha, merged, None)


def _is_newer(candidate: str, baseline: str) -> bool:
    try:
        return Version(candidate) > Version(baseline)
    except InvalidVersion:
        return False


__all__ = [
    "ReservedAlphaConfirmation",
    "confirm_reserved_alpha",
    "fetch_published_release_files",
    "release_files_from_version_payload",
    "with_confirmed_release",
]
