"""Stage Guard Cloud Review artifacts for editable PyInstaller builds."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

_ARTIFACTS = {
    "contracts/guard-cloud-review/v2/contract.json": "v2/contract.json",
    "contracts/guard-cloud-review/v2/command-result.json": "v2/command-result.json",
    "contracts/guard-cloud-review/v2/fixtures.json": "v2/fixtures.json",
    "docs/guard/contracts/guard-cloud-review.md": "guard-cloud-review.md",
}


def stage_artifacts(source_root: Path) -> tuple[Path, ...]:
    """Copy canonical artifacts into package data and return staged paths."""

    source_root = source_root.resolve()
    data_root = source_root / "src/codex_plugin_scanner/guard/contracts/data/guard-cloud-review"
    staged: list[Path] = []
    for source_name, destination_name in _ARTIFACTS.items():
        source = source_root / source_name
        if not source.is_file():
            raise FileNotFoundError(f"required Guard Cloud Review artifact is missing: {source_name}")
        destination = data_root / destination_name
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
