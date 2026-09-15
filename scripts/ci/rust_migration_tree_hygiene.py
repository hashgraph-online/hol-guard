#!/usr/bin/env python3
"""Reject retired one-shot Rust migration delivery residue."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections.abc import Sequence
from pathlib import Path

SCHEMA_VERSION = 1
RETIRED_PATHS = (
    ".github/rust-required-gzip-b64",
    ".github/rust-required-patch",
    "scripts/ci/apply_daemon_edge_hardening.py",
)
RETIRED_GITHUB_PREFIXES = ("rust-required-",)
RETIRED_WORKFLOW_PREFIXES = ("tmp-",)
RETIRED_WORKFLOW_MARKERS = ("shepherd",)
RETIRED_SCRIPT_GLOBS = (
    "apply_*rust*.py",
    "*rust*patch*.py",
    "*migration*applicator*.py",
)
RETIRED_BRANCH_REFS = (
    "feat/rust-p0-native-core-final",
    "fix/rust-daemon-ux-hardening-definitive",
    "fix/rust-p0-p2-regression-hardening",
    "fix/rust-required-no-python-runtime-fallback",
)


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def find_residue(root: Path) -> list[str]:
    """Return privacy-safe repository-relative paths for retired delivery artifacts."""

    root = root.resolve()
    found = {path for path in RETIRED_PATHS if (root / path).exists()}

    github = root / ".github"
    if github.is_dir():
        found.update(
            _relative(root, path)
            for path in github.iterdir()
            if path.name.startswith(RETIRED_GITHUB_PREFIXES)
        )

    workflows = github / "workflows"
    if workflows.is_dir():
        for path in workflows.iterdir():
            if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
                continue
            lowered_name = path.name.lower()
            if lowered_name.startswith(RETIRED_WORKFLOW_PREFIXES) or any(
                marker in lowered_name for marker in RETIRED_WORKFLOW_MARKERS
            ):
                found.add(_relative(root, path))
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                found.add(_relative(root, path))
                continue
            if any(branch in source for branch in RETIRED_BRANCH_REFS):
                found.add(_relative(root, path))

    scripts = root / "scripts" / "ci"
    if scripts.is_dir():
        for pattern in RETIRED_SCRIPT_GLOBS:
            found.update(
                _relative(root, path)
                for path in scripts.glob(pattern)
                if path.is_file()
            )

    return sorted(found)


def _self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="hol-guard-rust-hygiene-") as temporary:
        root = Path(temporary)
        payload = root / ".github" / "rust-required-transfer"
        payload.mkdir(parents=True)
        (payload / "part-000").write_text("retired\n", encoding="utf-8")

        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "tmp-apply-rust.yml").write_text("name: retired\n", encoding="utf-8")
        (workflows / "daemon-edge-cleanup-shepherd.yml").write_text(
            "name: retired\n",
            encoding="utf-8",
        )
        (workflows / "closed-branch.yml").write_text(
            "on:\n  push:\n    branches: [fix/rust-p0-p2-regression-hardening]\n",
            encoding="utf-8",
        )

        scripts = root / "scripts" / "ci"
        scripts.mkdir(parents=True)
        (scripts / "apply_daemon_edge_hardening.py").write_text(
            "raise SystemExit('retired')\n",
            encoding="utf-8",
        )
        (scripts / "apply_future_rust_patch.py").write_text(
            "raise SystemExit('retired')\n",
            encoding="utf-8",
        )

        expected = [
            ".github/rust-required-transfer",
            ".github/workflows/closed-branch.yml",
            ".github/workflows/daemon-edge-cleanup-shepherd.yml",
            ".github/workflows/tmp-apply-rust.yml",
            "scripts/ci/apply_daemon_edge_hardening.py",
            "scripts/ci/apply_future_rust_patch.py",
        ]
        actual = find_residue(root)
        if actual != expected:
            raise RuntimeError(f"tree-hygiene self-test failed: expected={expected!r}, actual={actual!r}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        _self_test()
        print(json.dumps({"schema_version": SCHEMA_VERSION, "self_test": "passed"}, sort_keys=True))
        return 0

    residue = find_residue(args.root)
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "retired_residue_count": len(residue),
                "retired_residue_paths": residue,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if residue else 0


if __name__ == "__main__":
    raise SystemExit(main())
