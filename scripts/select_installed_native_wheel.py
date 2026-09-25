"""Select the one Guard native wheel compatible with this canary runner."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from packaging.tags import sys_tags
from packaging.utils import parse_wheel_filename
from packaging.version import Version


def select_native_wheel(dist_dir: Path, version: str, output_dir: Path) -> Path:
    supported = set(sys_tags())
    expected = Version(version)
    matches: list[Path] = []
    # Wheel filenames use underscores; parse_wheel_filename returns the normalized hyphenated name.
    for wheel in sorted(dist_dir.glob("hol_guard-*.whl")):
        name, candidate_version, _build, tags = parse_wheel_filename(wheel.name)
        if (
            name == "hol-guard"
            and candidate_version == expected
            and any(tag.platform != "any" for tag in tags)
            and tags & supported
        ):
            if wheel.is_symlink() or not wheel.is_file():
                raise ValueError("compatible native Guard wheel is not a regular file")
            matches.append(wheel)
    if len(matches) != 1:
        raise ValueError(f"expected one compatible native Guard wheel, found {len(matches)}")
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("native canary selection directory is not empty")
    selected = output_dir / matches[0].name
    shutil.copyfile(matches[0], selected)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--dist-dir", type=Path, required=True)
    _ = parser.add_argument("--version", required=True)
    _ = parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(select_native_wheel(args.dist_dir, args.version, args.output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
