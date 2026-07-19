#!/usr/bin/env python3
"""Compute the next stable release version for a main-branch build."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable

from packaging.version import InvalidVersion, Version


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
        except InvalidVersion as exc:
            raise ValueError(f"Registry version is invalid: {version_text!r}") from exc
        if version_text != str(version) or version.local is not None:
            raise ValueError(f"Registry version is not canonical: {version_text!r}")
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
            latest = latest_main_release_version(base_version, payload)
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
