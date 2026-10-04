#!/usr/bin/env python3
"""Allow a stable dispatch to finish a published release whose GitHub files are missing.

The next registry version remains the normal path. A dispatch of the latest
PyPI version is accepted only when that version's GitHub release cannot yet
supply the Desktop updater: the pure wheel, the macOS arm64 wheel, or the
publish provenance bundle is absent. A complete release is not republished.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path

# Keep aligned with verify_native_runtime_release.EXPECTED_TARGETS. Stable
# versions are canonical X.Y.Z; wheel tags still use PEP 427's dash-to-underscore
# normalization so a pre-release form cannot miss its filename.
_NATIVE_PLATFORM_TAGS = (
    "manylinux_2_17_x86_64",
    "macosx_13_0_x86_64",
    "macosx_11_0_arm64",
    "win_amd64",
)


def _required_release_assets(version: str) -> set[str]:
    wheel_version = version.replace("-", "_")
    required = {
        f"hol_guard-{wheel_version}-py3-none-any.whl",
        f"hol_guard-{version}.tar.gz",
        f"hol-guard-v{version}.intoto.jsonl",
    }
    required.update(f"hol_guard-{wheel_version}-py3-none-{platform}.whl" for platform in _NATIVE_PLATFORM_TAGS)
    return required


def github_release_needs_asset_repair(version: str, asset_names: Iterable[str]) -> bool:
    names = {name.strip() for name in asset_names if name.strip()}
    return not _required_release_assets(version).issubset(names)


def stable_dispatch_is_allowed(
    *,
    requested: str,
    expected_next: str,
    latest_pypi: str,
    asset_names: Iterable[str] = (),
    release_missing: bool = False,
    deferred_pypi: bool = False,
) -> bool:
    if requested == expected_next:
        return True
    if deferred_pypi:
        return not release_missing and not github_release_needs_asset_repair(requested, asset_names)
    if not latest_pypi or requested != latest_pypi:
        return False
    if release_missing:
        return True
    return github_release_needs_asset_repair(requested, asset_names)


def _asset_names(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    return tuple(path.read_text(encoding="utf-8").splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requested", required=True)
    parser.add_argument("--expected-next", required=True)
    parser.add_argument("--latest-pypi", default="")
    parser.add_argument("--asset-names-file", type=Path)
    parser.add_argument("--release-missing", action="store_true")
    parser.add_argument(
        "--deferred-pypi",
        action="store_true",
        help="Allow recovery of a complete GitHub release that is still absent from PyPI",
    )
    args = parser.parse_args(argv)
    allowed = stable_dispatch_is_allowed(
        requested=args.requested,
        expected_next=args.expected_next,
        latest_pypi=args.latest_pypi,
        asset_names=_asset_names(args.asset_names_file),
        release_missing=bool(args.release_missing),
        deferred_pypi=bool(args.deferred_pypi),
    )
    return 0 if allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
