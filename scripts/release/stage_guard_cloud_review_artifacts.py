"""Stage Guard contract artifacts for editable PyInstaller builds."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

_ARTIFACTS = {
    "contracts/guard-cloud-review/v2/contract.json": "guard-cloud-review/v2/contract.json",
    "contracts/guard-cloud-review/v2/command-result.json": "guard-cloud-review/v2/command-result.json",
    "contracts/guard-cloud-review/v2/fixtures.json": "guard-cloud-review/v2/fixtures.json",
    "docs/guard/contracts/guard-cloud-review.md": "guard-cloud-review/guard-cloud-review.md",
    "contracts/extensions/trust-class-map.v1.json": "extensions/trust-class-map.v1.json",
    "contracts/extensions/contribution.v1.schema.json": "extensions/contribution.v1.schema.json",
    "contributions/extensions/command.blitcp.json": "extensions/contributions/command.blitcp.json",
    "contributions/extensions/command.dispat.json": "extensions/contributions/command.dispat.json",
    "contributions/extensions/command.noodle.json": "extensions/contributions/command.noodle.json",
    "contributions/extensions/command.probe.json": "extensions/contributions/command.probe.json",
    "contributions/extensions/command.repo2nb.json": "extensions/contributions/command.repo2nb.json",
    "contributions/extensions/command.skill-sunset.json": "extensions/contributions/command.skill-sunset.json",
    "contracts/mcp-servers/contribution.v1.schema.json": "mcp_servers/contribution.v1.schema.json",
    "contributions/mcp-servers/mcp.filesystem.json": "mcp_servers/contributions/mcp.filesystem.json",
}


def stage_artifacts(source_root: Path) -> tuple[Path, ...]:
    """Copy canonical artifacts into package data and return staged paths."""

    source_root = source_root.resolve()
    data_root = source_root / "src/codex_plugin_scanner/guard/contracts/data"
    staged: list[Path] = []
    for source_name, destination_name in _ARTIFACTS.items():
        source = source_root / source_name
        if not source.is_file():
            raise FileNotFoundError(f"required packaged contract artifact is missing: {source_name}")
        destination = data_root / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        staged.append(destination)
    for package in (
        data_root,
        data_root / "extensions",
        data_root / "extensions" / "contributions",
        data_root / "mcp_servers",
        data_root / "mcp_servers" / "contributions",
    ):
        package.mkdir(parents=True, exist_ok=True)
        init_path = package / "__init__.py"
        if not init_path.is_file():
            init_path.write_text("", encoding="utf-8")
        staged.append(init_path)
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
