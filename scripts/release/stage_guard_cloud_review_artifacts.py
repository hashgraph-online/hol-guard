"""Stage wheel force-include artifacts for editable PyInstaller builds."""

from __future__ import annotations

import argparse
import shutil
import tomllib
from pathlib import Path
from typing import Any

_FORCE_INCLUDE_KEYS = ("tool", "hatch", "build", "targets", "wheel", "force-include")


def _force_includes(pyproject: Path) -> dict[str, str]:
    with pyproject.open("rb") as handle:
        node: Any = tomllib.load(handle)
    for key in _FORCE_INCLUDE_KEYS:
        if not isinstance(node, dict) or key not in node:
            table = ".".join(_FORCE_INCLUDE_KEYS)
            raise ValueError(f"pyproject.toml is missing [{table}] mappings")
        node = node[key]
    if not isinstance(node, dict) or not node:
        raise ValueError("wheel force-include mappings must be a non-empty table")
    for source_name, destination_name in node.items():
        if not isinstance(source_name, str) or not isinstance(destination_name, str):
            raise ValueError("wheel force-include mappings must be string-to-string")
    return dict(node)


def stage_artifacts(source_root: Path) -> tuple[Path, ...]:
    """Copy every wheel force-include mapping into the source package tree.

    PyInstaller freezes build from the git source tree, where hatch's wheel
    force-include data (extension trust-class map, Guard Cloud Review
    contracts) has not been materialized yet. Without this staging, packaged
    resource lookups fail inside the frozen binary and fall back to
    repository-relative paths that do not exist on a build runner.
    """

    source_root = source_root.resolve()
    mappings = _force_includes(source_root / "pyproject.toml")
    staged: list[Path] = []
    for source_name, destination_name in mappings.items():
        source = source_root / source_name
        if not source.is_file():
            raise FileNotFoundError(f"required wheel artifact is missing: {source_name}")
        destination = source_root / "src" / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        staged.append(destination)
    return tuple(staged)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args()
    for path in stage_artifacts(args.source_root):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
