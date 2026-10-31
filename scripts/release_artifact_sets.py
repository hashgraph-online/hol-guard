"""Registry artifact subsets for HOL Guard publication."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Final

from packaging.utils import InvalidWheelFilename, parse_wheel_filename

ARTIFACT_SETS: Final = ("full", "wheels", "pure")
# Stable native wheels for these platforms ship on the GitHub release only. Few installs use them, and keeping
# them off PyPI keeps each release inside the project storage quota; clients fetch them from the release and
# verify them against the digest manifest embedded in the PyPI pure wheel.
GITHUB_ONLY_PLATFORM_TAGS: Final = frozenset({"macosx_13_0_x86_64", "manylinux_2_17_aarch64", "win_arm64"})


class ArtifactSetError(RuntimeError):
    """Raised when a registry artifact set cannot be selected."""


def sdist_name(version: str) -> str:
    return f"hol_guard-{version}.tar.gz"


def is_github_only_wheel(filename: str) -> bool:
    """True for a native wheel whose platform is published on the GitHub release but never on PyPI."""

    if not filename.endswith(".whl"):
        return False
    try:
        _name, _version, _build, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return False
    return any(tag.platform in GITHUB_ONLY_PLATFORM_TAGS for tag in tags)


def registry_wheels(filenames: Iterable[str]) -> list[str]:
    """Return the wheels a wheels-only registry upload carries: every wheel except GitHub-only platforms."""

    return sorted(name for name in filenames if name.endswith(".whl") and not is_github_only_wheel(name))


def select_upload_artifacts(local: Mapping[str, str], *, version: str, artifact_set: str) -> dict[str, str]:
    """Return the registry subset that this publication is allowed to upload.

    ``version`` must already be canonical.
    """

    if artifact_set == "full":
        return dict(local)
    if artifact_set == "wheels":
        # The sdist stays on the GitHub release; pip never selects it because the pure wheel matches everywhere.
        # GitHub-only native wheels stay there too.
        return {
            filename: digest
            for filename, digest in local.items()
            if filename != sdist_name(version) and not is_github_only_wheel(filename)
        }
    if artifact_set != "pure":
        raise ArtifactSetError("Unsupported Guard registry artifact set")
    wheel = f"hol_guard-{version.replace('-', '_')}-py3-none-any.whl"
    digest = local.get(wheel)
    if digest is None:
        raise ArtifactSetError("Guard pure wheel is missing from the local release set")
    return {wheel: digest}


def remote_for_artifact_set(
    remote: Mapping[str, str],
    complete: Mapping[str, str],
    *,
    version: str,
    artifact_set: str,
) -> dict[str, str]:
    """Drop a registry sdist that predates wheels-only publication when its bytes are the local sdist."""

    sdist = sdist_name(version)
    if artifact_set == "wheels" and sdist in remote and remote[sdist] == complete.get(sdist):
        return {filename: digest for filename, digest in remote.items() if filename != sdist}
    return dict(remote)


def stage_registry_wheels(dist_dir: Path, output_dir: Path) -> list[str]:
    """Copy the wheels-only registry upload set from ``dist_dir`` into an empty ``output_dir``."""

    if not dist_dir.is_dir() or dist_dir.is_symlink():
        raise ArtifactSetError("Distribution directory must be a regular directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink() or any(output_dir.iterdir()):
        raise ArtifactSetError("Registry staging directory must be a new empty directory")
    staged = registry_wheels(path.name for path in dist_dir.iterdir() if path.is_file() and not path.is_symlink())
    if not staged:
        raise ArtifactSetError("Distribution directory has no registry wheels")
    for name in staged:
        shutil.copyfile(dist_dir / name, output_dir / name)
    return staged


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage-pypi", help="Copy the wheels-only registry upload set")
    stage.add_argument("--dist-dir", type=Path, required=True)
    stage.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        staged = stage_registry_wheels(args.dist_dir, args.output_dir)
    except (ArtifactSetError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "staged", "files": staged}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
