#!/usr/bin/env python3
"""Run one reviewed mutmut target from an isolated temporary workspace."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.mutation_targets import TARGETS, MutationTarget, render_mutmut_config

ROOT: Final = Path(__file__).resolve().parents[2]


def prepare_workspace(root: Path, target: MutationTarget, workspace: Path) -> Path:
    """Create the minimal root mutmut needs without altering the checked-out project."""

    workspace.mkdir(parents=True, exist_ok=True)
    for name in ("src", "tests"):
        (workspace / name).symlink_to(root / name, target_is_directory=True)
    config_path = workspace / "pyproject.toml"
    config_path.write_text(render_mutmut_config(target), encoding="utf-8")
    return config_path


def run_target(root: Path, target: MutationTarget, output_dir: Path, max_children: int) -> Path:
    """Run mutmut and retain its summary plus per-mutant status metadata."""

    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / f"{target.name}.json"
    metadata_path = output_dir / f"{target.name}.meta"
    with tempfile.TemporaryDirectory(prefix=f"guard-mutmut-{target.name}-") as directory:
        workspace = Path(directory)
        _ = prepare_workspace(root, target, workspace)
        for arguments in (
            ("run", "--max-children", str(max_children)),
            ("export-cicd-stats",),
        ):
            subprocess.run(
                [sys.executable, "-m", "mutmut", *arguments],
                cwd=workspace,
                check=True,
            )
        shutil.copy2(workspace / "mutants" / "mutmut-cicd-stats.json", summary_path)
        shutil.copy2(workspace / "mutants" / f"{target.source_path}.meta", metadata_path)
    return summary_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one isolated HOL Guard mutation target.")
    _ = parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    _ = parser.add_argument("--output-dir", type=Path, default=Path("artifacts/mutation"))
    _ = parser.add_argument("--max-children", type=int, default=4)
    _ = parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.max_children < 1:
        parser.error("--max-children must be positive")
    target = TARGETS[args.target]
    if args.dry_run:
        print(json.dumps({"target": target.name, "source_path": target.source_path}, sort_keys=True))
        return 0
    summary_path = run_target(ROOT, target, args.output_dir, args.max_children)
    print(json.dumps({"summary": str(summary_path), "target": target.name}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
