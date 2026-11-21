"""Emit per-workspace-member release profile overrides for fast alpha codegen builds."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

_MEMBER_NAME = re.compile(r"[A-Za-z0-9_-]+")
_OPT_LEVELS = ("0", "1", "2", "3", "s", "z")


def load_metadata(manifest_path: Path, metadata_file: Path | None) -> dict:
    """Return cargo metadata for the workspace manifest."""
    if metadata_file is not None:
        return json.loads(metadata_file.read_text(encoding="utf-8"))
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--manifest-path",
            str(manifest_path),
            "--no-deps",
            "--format-version",
            "1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ValueError(f"cargo metadata failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def workspace_member_names(metadata: dict) -> list[str]:
    """Return sorted package names for workspace members only."""
    member_ids = set(metadata.get("workspace_members") or [])
    names = sorted(package["name"] for package in metadata.get("packages", []) if package.get("id") in member_ids)
    for name in names:
        if not _MEMBER_NAME.fullmatch(name):
            raise ValueError(f"invalid workspace member name: {name!r}")
    if not names:
        raise ValueError("cargo metadata reports no workspace members")
    return names


def render_profile(names: list[str], opt_level: str) -> str:
    """Render a cargo config fragment that overrides opt-level only for the named members."""
    value = opt_level if opt_level.isdigit() else json.dumps(opt_level)
    return "".join(f'[profile.release.package."{name}"]\nopt-level = {value}\n\n' for name in names)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opt-level", required=True, choices=_OPT_LEVELS)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-path", type=Path, default=Path("rust/Cargo.toml"))
    parser.add_argument(
        "--metadata",
        type=Path,
        help="Read cargo-metadata JSON from a file instead of running cargo metadata",
    )
    args = parser.parse_args(argv)

    names = workspace_member_names(load_metadata(args.manifest_path, args.metadata))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_profile(names, args.opt_level), encoding="utf-8")
    print(f"Wrote opt-level {args.opt_level} overrides for {len(names)} workspace members to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
