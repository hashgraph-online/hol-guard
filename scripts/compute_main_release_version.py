#!/usr/bin/env python3
"""Compute the next stable release version for a main-branch build."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from typing import Literal

from packaging.version import InvalidVersion, Version

PyPIReleaseState = Literal["absent", "active", "yanked"]
PyPIReleaseStateLoader = Callable[[str], PyPIReleaseState]
_PYPI_RELEASE_METADATA_LIMIT = 4 * 1024 * 1024


def _canonical_stable(version_text: str, *, label: str) -> Version:
    try:
        version = Version(version_text)
    except InvalidVersion as exc:
        raise ValueError(f"{label} is not a valid PEP 440 version: {version_text!r}") from exc
    if (
        version_text != str(version)
        or len(version.release) != 3
        or version.pre is not None
        or version.dev is not None
        or version.post is not None
        or version.local is not None
    ):
        raise ValueError(f"{label} must be a canonical X.Y.Z stable version")
    return version


def _stable_versions_for_line(base: Version, existing_versions: Iterable[str]) -> list[Version]:
    same_line: list[Version] = []

    for version_text in existing_versions:
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue
        if version_text != str(version) or version.local is not None:
            continue
        if (
            version.release[:2] == base.release[:2]
            and len(version.release) == 3
            and version.epoch == 0
            and version.pre is None
            and version.dev is None
            and version.post is None
        ):
            same_line.append(version)

    return same_line


def latest_main_release_version(base_version: str, existing_versions: Iterable[str]) -> str | None:
    base = _canonical_stable(base_version, label="Repository version")
    same_line = _stable_versions_for_line(base, existing_versions)
    return str(max(same_line)) if same_line else None


def compute_main_release_version(base_version: str, existing_versions: Iterable[str]) -> str:
    base = _canonical_stable(base_version, label="Repository version")
    same_line = _stable_versions_for_line(base, existing_versions)

    if not same_line:
        return str(base)

    latest = max(same_line)
    next_registry = Version(f"{base.major}.{base.minor}.{latest.micro + 1}")
    return str(max(base, next_registry))


def _pypi_release_state(version_text: str) -> PyPIReleaseState:
    """Return whether an exact PyPI release is absent, active, or fully yanked."""
    quoted_version = urllib.parse.quote(version_text, safe="")
    url = f"https://pypi.org/pypi/hol-guard/{quoted_version}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "hol-guard-main-release-version"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None:
                try:
                    parsed_length = int(declared_length)
                except ValueError as exc:
                    raise ValueError("PyPI release metadata has an invalid content length") from exc
                if parsed_length < 0 or parsed_length > _PYPI_RELEASE_METADATA_LIMIT:
                    raise ValueError("PyPI release metadata exceeds the maximum allowed size")
            payload = response.read(_PYPI_RELEASE_METADATA_LIMIT + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "absent"
        raise ValueError(f"PyPI release lookup failed with HTTP {exc.code}") from exc
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise ValueError("PyPI release lookup failed") from exc

    if len(payload) > _PYPI_RELEASE_METADATA_LIMIT:
        raise ValueError("PyPI release metadata exceeds the maximum allowed size")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("PyPI release metadata returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("PyPI release metadata must be a JSON object")
    info = document.get("info")
    if not isinstance(info, dict) or info.get("version") != version_text:
        raise ValueError("PyPI release metadata returned the wrong version")
    urls = document.get("urls")
    if not isinstance(urls, list):
        raise ValueError("PyPI release metadata is missing the release files")
    if not urls:
        raise ValueError("PyPI release metadata is missing the release files")

    yanked_flags: list[bool] = []
    for item in urls:
        if not isinstance(item, dict):
            raise ValueError("PyPI release file metadata must be a JSON object")
        yanked = item.get("yanked")
        if not isinstance(yanked, bool):
            raise ValueError("PyPI release file metadata is missing the yanked state")
        yanked_flags.append(yanked)
    return "yanked" if all(yanked_flags) else "active"


def latest_unyanked_main_release_version(
    base_version: str,
    existing_versions: Iterable[str],
    *,
    release_state_loader: PyPIReleaseStateLoader = _pypi_release_state,
) -> str | None:
    """Return the latest stable ancestry anchor, ignoring fully yanked PyPI releases.

    Versions absent from PyPI remain eligible. The main publication workflow includes its
    not-yet-published candidate in the race check, so an absent candidate must not be
    discarded. An active PyPI release remains an ancestry anchor and will still require
    its corresponding Git tag in the workflow.
    """
    base = _canonical_stable(base_version, label="Repository version")
    same_line = sorted(_stable_versions_for_line(base, existing_versions), reverse=True)
    for version in same_line:
        version_text = str(version)
        if release_state_loader(version_text) != "yanked":
            return version_text
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--base-version", required=True)
    _ = parser.add_argument("--latest-existing", action="store_true")
    args = parser.parse_args()
    base_version = str(args.base_version)
    latest_existing = bool(args.latest_existing)

    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise ValueError("Registry versions must be a JSON array of strings")
        if latest_existing:
            latest = latest_unyanked_main_release_version(base_version, payload)
            if latest is not None:
                print(latest)
        else:
            print(compute_main_release_version(base_version, payload))
    except (json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
