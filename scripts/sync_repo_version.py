#!/usr/bin/env python3
"""Keep repository version files aligned."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

PYPROJECT_RELATIVE_PATH = Path("pyproject.toml")
MODULE_RELATIVE_PATH = Path("src/codex_plugin_scanner/version.py")
LOCKFILE_RELATIVE_PATH = Path("uv.lock")
TOML_TABLE_HEADER_PATTERN = re.compile(r"^\[[A-Za-z0-9_.-]+\]$")
PYPROJECT_VERSION_LINE_PATTERN = re.compile(
    r'^(?P<prefix>\s*version\s*=\s*["\'])(?P<version>[^"\']+)(?P<suffix>["\'](?:\s+#.*)?\s*)$'
)
MODULE_VERSION_LINE_PATTERN = re.compile(
    r'^(?P<prefix>\s*__version__\s*=\s*["\'])(?P<version>[^"\']+)(?P<suffix>["\'](?:\s+#.*)?\s*)$',
    re.MULTILINE,
)


@dataclass(frozen=True)
class RepoVersionState:
    pyproject: str
    module: str
    lockfile: str


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _validate_version_token(version: str) -> str:
    try:
        Version(version)
    except InvalidVersion as exc:
        raise ValueError(f"Unsupported version format: {version}") from exc
    return version


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_pyproject_version(path: Path) -> str:
    project = tomllib.loads(_read_text(path)).get("project")
    if not isinstance(project, dict):
        raise ValueError(f"Could not find [project] table in {path}")
    version = project.get("version")
    if not isinstance(version, str):
        raise ValueError(f"Could not find [project].version in {path}")
    return version


def _extract_version(path: Path, pattern: re.Pattern[str], label: str) -> str:
    match = pattern.search(_read_text(path))
    if match is None:
        raise ValueError(f"Could not find {label} version in {path}")
    return match.group("version")


def read_repo_version_state(repo_root: Path) -> RepoVersionState:
    return RepoVersionState(
        pyproject=_read_pyproject_version(repo_root / PYPROJECT_RELATIVE_PATH),
        module=_extract_version(
            repo_root / MODULE_RELATIVE_PATH,
            MODULE_VERSION_LINE_PATTERN,
            "module",
        ),
        lockfile=_read_lockfile_version(repo_root / LOCKFILE_RELATIVE_PATH),
    )


def assert_repo_version(repo_root: Path, expected_version: str | None = None) -> str:
    if expected_version is not None:
        _validate_version_token(expected_version)
    state = read_repo_version_state(repo_root)
    if state.pyproject != state.module or state.pyproject != state.lockfile:
        raise ValueError(
            "Repository version mismatch: "
            f"{PYPROJECT_RELATIVE_PATH} has {state.pyproject}, "
            f"{MODULE_RELATIVE_PATH} has {state.module}, "
            f"{LOCKFILE_RELATIVE_PATH} has {state.lockfile}"
        )
    if expected_version is not None and state.pyproject != expected_version:
        raise ValueError(f"Repository version mismatch: expected {expected_version}, found {state.pyproject}")
    return state.pyproject


def _replace_matching_line(line: str, pattern: re.Pattern[str], version: str) -> str:
    line_body = line.rstrip("\r\n")
    line_ending = line[len(line_body) :]
    match = pattern.match(line_body)
    if match is None:
        return line
    return f"{match.group('prefix')}{version}{match.group('suffix')}{line_ending}"


def _replace_project_version(path: Path, version: str) -> tuple[str, bool]:
    text = _read_text(path)
    lines = text.splitlines(keepends=True)
    in_project_table = False
    project_version_index: int | None = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[project]":
            in_project_table = True
            continue
        if in_project_table and TOML_TABLE_HEADER_PATTERN.fullmatch(stripped):
            break
        if not in_project_table:
            continue
        if PYPROJECT_VERSION_LINE_PATTERN.match(line.rstrip("\r\n")) is not None:
            lines[index] = _replace_matching_line(line, PYPROJECT_VERSION_LINE_PATTERN, version)
            project_version_index = index
            break

    if project_version_index is None:
        raise ValueError(f"Could not update [project].version in {path}")

    updated_text = "".join(lines)
    return updated_text, updated_text != text


def _replace_module_version(path: Path, version: str) -> tuple[str, bool]:
    text = _read_text(path)
    lines = text.splitlines(keepends=True)
    module_version_index: int | None = None

    for index, line in enumerate(lines):
        if MODULE_VERSION_LINE_PATTERN.match(line.rstrip("\r\n")) is not None:
            lines[index] = _replace_matching_line(line, MODULE_VERSION_LINE_PATTERN, version)
            module_version_index = index
            break

    if module_version_index is None:
        raise ValueError(f"Could not update module version line in {path}")

    updated_text = "".join(lines)
    return updated_text, updated_text != text


def _find_lockfile_version_index(lines: list[str], path: Path) -> int:
    in_package_block = False
    package_name_matches = False
    editable_source_matches = False
    version_index: int | None = None

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[[package]]":
            if in_package_block and package_name_matches and editable_source_matches and version_index is not None:
                return version_index
            in_package_block = True
            package_name_matches = False
            editable_source_matches = False
            version_index = None
            continue
        if not in_package_block:
            continue
        if stripped.startswith("name = "):
            package_name_matches = stripped == 'name = "hol-guard"'
            continue
        if stripped.startswith("version = ") and version_index is None:
            version_index = index
            continue
        if stripped.startswith("source = "):
            editable_source_matches = stripped == 'source = { editable = "." }'

    if in_package_block and package_name_matches and editable_source_matches and version_index is not None:
        return version_index
    raise ValueError(f"Could not find editable hol-guard package version in {path}")


def _read_lockfile_version(path: Path) -> str:
    lines = _read_text(path).splitlines(keepends=True)
    version_index = _find_lockfile_version_index(lines, path)
    version_line = lines[version_index].rstrip("\r\n")
    match = PYPROJECT_VERSION_LINE_PATTERN.match(version_line)
    if match is None:
        raise ValueError(f"Could not parse lockfile version in {path}")
    return match.group("version")


def _replace_lockfile_version(path: Path, version: str) -> tuple[str, bool]:
    lines = _read_text(path).splitlines(keepends=True)
    version_index = _find_lockfile_version_index(lines, path)
    replaced_line = _replace_matching_line(lines[version_index], PYPROJECT_VERSION_LINE_PATTERN, version)
    if replaced_line == lines[version_index]:
        return "".join(lines), False
    lines[version_index] = replaced_line
    return "".join(lines), True


def sync_repo_version(repo_root: Path, version: str) -> bool:
    normalized_version = _validate_version_token(version)
    pyproject_path = repo_root / PYPROJECT_RELATIVE_PATH
    module_path = repo_root / MODULE_RELATIVE_PATH
    lockfile_path = repo_root / LOCKFILE_RELATIVE_PATH

    pyproject_text, pyproject_changed = _replace_project_version(pyproject_path, normalized_version)
    module_text, module_changed = _replace_module_version(module_path, normalized_version)
    lockfile_text, lockfile_changed = _replace_lockfile_version(lockfile_path, normalized_version)

    if pyproject_changed:
        pyproject_path.write_text(pyproject_text, encoding="utf-8")
    if module_changed:
        module_path.write_text(module_text, encoding="utf-8")
    if lockfile_changed:
        lockfile_path.write_text(lockfile_text, encoding="utf-8")

    assert_repo_version(repo_root, normalized_version)
    return pyproject_changed or module_changed or lockfile_changed


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
    try:
        if args.version is not None:
            sync_repo_version(repo_root, args.version)
            print(_validate_version_token(args.version))
            return 0
        current_version = assert_repo_version(repo_root)
        print(current_version)
        return 0
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
