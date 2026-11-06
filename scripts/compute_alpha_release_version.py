#!/usr/bin/env python3
"""Compute the next alpha version for an authorized release train."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from typing import cast

from packaging.version import InvalidVersion, Version

try:
    from scripts.validate_alpha_release import main_alpha_train
except ModuleNotFoundError:  # Run directly as scripts/compute_alpha_release_version.py.
    from validate_alpha_release import main_alpha_train

SUPPORTED_TRAINS = {"2.2": (2, 2, 0), "3.0": (3, 0, 1), "3.1": (3, 1, 0)}
MAIN_TRAIN = "main"


def _train_release(release_train: str, base_version: str | None) -> tuple[int, int, int]:
    if release_train == MAIN_TRAIN:
        if base_version is None:
            raise ValueError("The main alpha train requires --base-version")
        train = main_alpha_train(base_version)
        return (train.major, train.minor, train.patch)
    release = SUPPORTED_TRAINS.get(release_train)
    if release is None:
        raise ValueError(f"Unsupported alpha release train: {release_train}")
    return release


def _alpha_versions(release_train: str, existing_versions: Iterable[str], base_version: str | None = None) -> list[int]:
    release = _train_release(release_train, base_version)

    alpha_numbers: list[int] = []
    for version_text in existing_versions:
        try:
            version = Version(version_text)
        except InvalidVersion as exc:
            raise ValueError(f"Existing version is invalid: {version_text!r}") from exc
        if version_text != str(version) or version.local is not None:
            raise ValueError(f"Existing version is not canonical: {version_text!r}")
        if version.release != release:
            continue
        if version.post is not None:
            raise ValueError(f"Existing post release {version} closes the alpha phase for train {release_train}")
        if version.pre is None and version.dev is None and version.post is None:
            raise ValueError(f"Existing stable release {version} closes release train {release_train}")
        if version.pre is not None and version.pre[0] != "a":
            raise ValueError(
                f"Existing non-alpha prerelease {version} closes the alpha phase for train {release_train}"
            )
        if version.pre is not None and version.pre[0] == "a" and version.dev is not None:
            raise ValueError(f"Existing alpha development release {version} is not a public alpha reservation")
        if version.pre is not None and version.pre[0] == "a":
            alpha_numbers.append(version.pre[1])

    return alpha_numbers


def validate_alpha_phase_open(
    release_train: str, existing_versions: Iterable[str], base_version: str | None = None
) -> None:
    _ = _alpha_versions(release_train, existing_versions, base_version)


def compute_alpha_release_version(
    release_train: str, existing_versions: Iterable[str], base_version: str | None = None
) -> str:
    alpha_numbers = _alpha_versions(release_train, existing_versions, base_version)
    version_prefix = ".".join(str(part) for part in _train_release(release_train, base_version))

    next_alpha = max(alpha_numbers, default=0) + 1
    return f"{version_prefix}a{next_alpha}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--release-train", required=True)
    _ = parser.add_argument("--validate-phase-only", action="store_true")
    _ = parser.add_argument("--base-version", help="Current stable base version; required for the main train")
    args = parser.parse_args()

    try:
        payload = cast(object, json.load(sys.stdin))
        if not isinstance(payload, list):
            raise ValueError("Registry versions must be a JSON array of strings")
        items = cast(list[object], payload)
        if not all(isinstance(item, str) for item in items):
            raise ValueError("Registry versions must be a JSON array of strings")
        existing_versions = cast(list[str], items)
        release_train = cast(str, args.release_train)
        validate_phase_only = cast(bool, args.validate_phase_only)
        base_version = cast(str | None, args.base_version)
        if validate_phase_only:
            validate_alpha_phase_open(release_train, existing_versions, base_version)
        else:
            print(compute_alpha_release_version(release_train, existing_versions, base_version))
    except (json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
