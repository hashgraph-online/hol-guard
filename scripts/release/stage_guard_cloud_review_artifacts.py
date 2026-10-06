"""Stage Guard contract artifacts for editable PyInstaller builds."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

_STATIC_ARTIFACTS = {
    "contracts/extensions/native-command-program.v1.json": "extensions/native-command-program.v1.json",
    "contracts/guard-cloud-review/v2/contract.json": "guard-cloud-review/v2/contract.json",
    "contracts/guard-cloud-review/v2/command-result.json": "guard-cloud-review/v2/command-result.json",
    "contracts/guard-cloud-review/v2/fixtures.json": "guard-cloud-review/v2/fixtures.json",
    "docs/guard/contracts/guard-cloud-review.md": "guard-cloud-review/guard-cloud-review.md",
    "contracts/extensions/trust-class-map.v1.json": "extensions/trust-class-map.v1.json",
    "contracts/extensions/contribution.v1.schema.json": "extensions/contribution.v1.schema.json",
    "contracts/mcp-servers/contribution.v1.schema.json": "mcp_servers/contribution.v1.schema.json",
}

# Contribution payloads are enumerated, not listed: every regular JSON file
# present in the contributions tree is staged so a new contribution never
# needs to edit this script.
_CONTRIBUTION_SOURCES = (
    ("contributions/extensions", "command.*.json", "extensions/contributions"),
    ("contributions/mcp-servers", "mcp.*.json", "mcp_servers/contributions"),
)


def _artifacts(source_root: Path) -> dict[str, str]:
    artifacts = dict(_STATIC_ARTIFACTS)
    for relative_dir, pattern, destination_dir in _CONTRIBUTION_SOURCES:
        source_dir = source_root / relative_dir
        if not source_dir.is_dir():
            raise FileNotFoundError(f"required contribution directory is missing: {relative_dir}")
        matched = [path for path in sorted(source_dir.glob(pattern)) if path.is_file() and not path.is_symlink()]
        if not matched:
            raise FileNotFoundError(f"required contribution directory holds no payloads: {relative_dir} ({pattern})")
        for path in matched:
            artifacts[path.relative_to(source_root).as_posix()] = f"{destination_dir}/{path.name}"
    return artifacts


def stage_artifacts(source_root: Path, *, destination_root: Path | None = None) -> tuple[Path, ...]:
    """Copy canonical artifacts into package data and return staged paths."""

    source_root = source_root.resolve()
    data_root = (
        destination_root.resolve()
        if destination_root is not None
        else source_root / "src/codex_plugin_scanner/guard/contracts/data"
    )
    # Validate the complete artifact map before touching staged files so a
    # missing source can never leave a half-staged bundle behind.
    artifacts = _artifacts(source_root)
    for source_name in artifacts:
        if not (source_root / source_name).is_file():
            raise FileNotFoundError(f"required packaged contract artifact is missing: {source_name}")
    # Stale copies of removed contributions must not linger in a bundle: the
    # contribution destinations hold only staged payloads, so reset them.
    for _relative_dir, _pattern, destination_dir in _CONTRIBUTION_SOURCES:
        staged_dir = data_root / destination_dir
        if staged_dir.is_dir():
            shutil.rmtree(staged_dir)
    staged: list[Path] = []
    for source_name, destination_name in artifacts.items():
        source = source_root / source_name
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
    parser.add_argument("--destination-root", type=Path)
    args = parser.parse_args()
    for path in stage_artifacts(args.source_root, destination_root=args.destination_root):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
