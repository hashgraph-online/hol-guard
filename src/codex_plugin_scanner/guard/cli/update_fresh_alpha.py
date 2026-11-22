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
from typing import Any

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
        http.client.IncompleteRead,
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


__all__ = [
    "fetch_published_release_files",
    "release_files_from_version_payload",
    "with_confirmed_release",
]
