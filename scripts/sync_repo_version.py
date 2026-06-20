#!/usr/bin/env python3
"""Keep repository version files aligned."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

PYPROJECT_RELATIVE_PATH = Path("pyproject.toml")
MODULE_RELATIVE_PATH = Path("src/codex_plugin_scanner/version.py")
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
PYPROJECT_VERSION_PATTERN = re.compile(r'(?m)^version = "[^"]+"$')
MODULE_VERSION_PATTERN = re.compile(r'(?m)^__version__ = "[^"]+"$')


@dataclass(frozen=True)
class RepoVersionState:
    pyproject: str
    module: str


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _validate_semver(version: str) -> str:
    if not SEMVER_PATTERN.fullmatch(version):
        raise ValueError(f"Unsupported version format: {version}")
    return version


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_version(path: Path, pattern: re.Pattern[str], label: str) -> str:
    match = pattern.search(_read_text(path))
    if match is None:
        raise ValueError(f"Could not find {label} version in {path}")
    return match.group(0).split('"')[1]


def read_repo_version_state(repo_root: Path) -> RepoVersionState:
    return RepoVersionState(
        pyproject=_extract_version(
            repo_root / PYPROJECT_RELATIVE_PATH,
            PYPROJECT_VERSION_PATTERN,
            "pyproject",
        ),
        module=_extract_version(
            repo_root / MODULE_RELATIVE_PATH,
            MODULE_VERSION_PATTERN,
            "module",
        ),
    )


def assert_repo_version(repo_root: Path, expected_version: str | None = None) -> str:
    if expected_version is not None:
        _validate_semver(expected_version)
    state = read_repo_version_state(repo_root)
    if state.pyproject != state.module:
        raise ValueError(
            "Repository version mismatch: "
            f"{PYPROJECT_RELATIVE_PATH} has {state.pyproject}, "
            f"{MODULE_RELATIVE_PATH} has {state.module}"
        )
    if expected_version is not None and state.pyproject != expected_version:
        raise ValueError(
            "Repository version mismatch: "
            f"expected {expected_version}, found {state.pyproject}"
        )
    return state.pyproject


def _replace_single_line(path: Path, pattern: re.Pattern[str], replacement: str) -> bool:
    text = _read_text(path)
    updated_text, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise ValueError(f"Could not update version line in {path}")
    if updated_text == text:
        return False
    path.write_text(updated_text, encoding="utf-8")
    return True


def sync_repo_version(repo_root: Path, version: str) -> bool:
    normalized_version = _validate_semver(version)
    pyproject_changed = _replace_single_line(
        repo_root / PYPROJECT_RELATIVE_PATH,
        PYPROJECT_VERSION_PATTERN,
        f'version = "{normalized_version}"',
    )
    module_changed = _replace_single_line(
        repo_root / MODULE_RELATIVE_PATH,
        MODULE_VERSION_PATTERN,
        f'__version__ = "{normalized_version}"',
    )
    assert_repo_version(repo_root, normalized_version)
    return pyproject_changed or module_changed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="Validate that repository version files match and print the current version.",
    )
    mode.add_argument(
        "--version",
        help="Sync both repository version files to the supplied semantic version.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=_default_repo_root(),
        help="Repository root to inspect. Defaults to the current hol-guard checkout.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    if args.version is not None:
        sync_repo_version(repo_root, args.version)
        print(_validate_semver(args.version))
        return 0
    current_version = assert_repo_version(repo_root)
    print(current_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
