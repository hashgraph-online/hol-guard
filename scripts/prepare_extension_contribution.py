#!/usr/bin/env python3
"""Validate declarative extension fixtures and synchronize checked-in projections.

This maintainer command only invokes the reviewed native source compiler and
repository-owned deterministic projection scripts. It never executes a target
command from a contributor fixture.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PREFIX = "contributions/command-sources/"
FIXTURE_PREFIX = "tests/fixtures/command-source-"
MAX_FIXTURE_BYTES = 1_048_576


def _relative(path: Path) -> str:
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise ValueError("Source and fixture paths must remain inside this repository.") from error


def _load_object(path: Path) -> dict[str, object]:
    relative = _relative(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FIXTURE_BYTES:
        raise ValueError(f"Invalid declarative fixture input: {relative}")
    try:
        value = json.loads(path.read_bytes())
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {relative}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Expected an object in {relative}")
    return value


def _extension_id(source: dict[str, object], path: Path) -> str:
    extension = source.get("extension")
    if not isinstance(extension, dict) or not isinstance(extension.get("extension_id"), str):
        raise ValueError(f"Source has no extension identity: {_relative(path)}")
    extension_id = extension["extension_id"]
    if not extension_id.startswith("command."):
        raise ValueError(f"Source has an invalid command identity: {_relative(path)}")
    if _relative(path) != f"{SOURCE_PREFIX}{extension_id}.json":
        raise ValueError(f"Source filename does not match its extension identity: {_relative(path)}")
    return extension_id


def _fixture_source_ids(fixture: dict[str, object], path: Path | str) -> dict[str, dict[str, object]]:
    label = path if isinstance(path, str) else _relative(path)
    build = fixture.get("build")
    sources = build.get("sources") if isinstance(build, dict) else None
    if fixture.get("schema") != "guard.command-extension-fixtures.v1" or not isinstance(sources, list):
        raise ValueError(f"Fixture has no valid native build envelope: {label}")
    result: dict[str, dict[str, object]] = {}
    for item in sources:
        if not isinstance(item, dict):
            raise ValueError(f"Fixture has an invalid source envelope: {label}")
        extension = item.get("extension")
        extension_id = extension.get("extension_id") if isinstance(extension, dict) else None
        if not isinstance(extension_id, str) or extension_id in result:
            raise ValueError(f"Fixture source identities are invalid: {label}")
        result[extension_id] = item
    return result


def _fixtures() -> list[Path]:
    parent = ROOT / "tests/fixtures"
    return sorted(path for path in parent.glob("command-source-*.v1.json") if path.is_file() and not path.is_symlink())


def _changed_paths(revision: str) -> set[str]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "diff",
            "--name-only",
            "--diff-filter=ACMRD",
            f"{revision}...HEAD",
            "--",
            "contributions/command-sources",
            "tests/fixtures",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        raise ValueError("Could not determine the changed declarative contribution inputs.")
    return {line for line in completed.stdout.splitlines() if line}


def _previous_fixture_source_ids(revision: str, relative_path: str) -> dict[str, dict[str, object]]:
    completed = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{revision}:{relative_path}"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode or len(completed.stdout) > MAX_FIXTURE_BYTES:
        raise ValueError(f"Could not inspect the deleted portable fixture: {relative_path}")
    try:
        fixture = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"Invalid JSON in {relative_path} at the comparison revision") from error
    if not isinstance(fixture, dict):
        raise ValueError(f"Expected an object in {relative_path} at the comparison revision")
    return _fixture_source_ids(fixture, relative_path)


def _compiler(path: Path | None) -> Path:
    if path is not None:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.is_symlink():
            raise ValueError("The native source compiler must be a regular executable.")
        return resolved
    build = subprocess.run(
        [
            "cargo",
            "+1.88.0",
            "build",
            "--locked",
            "--manifest-path",
            str(ROOT / "rust/Cargo.toml"),
            "-p",
            "guard-command",
            "--bin",
            "guard-command-source",
        ],
        timeout=600,
        check=False,
    )
    if build.returncode:
        raise ValueError("Native source compiler build failed.")
    candidate = ROOT / "rust/target/debug/guard-command-source"
    if sys.platform == "win32":
        candidate = candidate.with_suffix(".exe")
    return candidate.resolve(strict=True)


def _run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        command,
        input=input_bytes,
        capture_output=True,
        timeout=600,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode(errors="replace").strip() or completed.stdout.decode(errors="replace").strip()
        raise ValueError(detail[:1024] or "Declarative contribution preparation failed.")
    return completed.stdout


def _validate_fixture(compiler: Path, path: Path) -> str:
    fixture = _load_object(path)
    result = _run([str(compiler), "test"], input_bytes=path.read_bytes())
    try:
        payload = json.loads(result)
    except json.JSONDecodeError as error:
        raise ValueError(f"Native fixture result was invalid: {_relative(path)}") from error
    if not isinstance(payload, dict) or payload.get("ok") is not True or payload.get("target_commands_executed") != 0:
        raise ValueError(f"Native fixture did not pass without target execution: {_relative(path)}")
    _ = _fixture_source_ids(fixture, path)
    return _relative(path)


def _validate_changed_source_fixture_pairs(
    changed: set[str], fixture_paths: list[Path], *, revision: str | None = None
) -> list[Path]:
    fixture_sources = {path: _fixture_source_ids(_load_object(path), path) for path in fixture_paths}
    affected_ids: set[str] = set()
    for relative_path in sorted(changed):
        if relative_path.startswith(SOURCE_PREFIX):
            path = ROOT / relative_path
            if not path.is_file():
                continue
            source = _load_object(path)
            affected_ids.add(_extension_id(source, path))
            continue
        if not relative_path.startswith(FIXTURE_PREFIX) or not relative_path.endswith(".v1.json"):
            continue
        path = ROOT / relative_path
        if path.is_file():
            changed_fixture_sources = _fixture_source_ids(_load_object(path), path)
            for extension_id, fixture_source in changed_fixture_sources.items():
                source_path = ROOT / f"{SOURCE_PREFIX}{extension_id}.json"
                if not source_path.is_file() or _load_object(source_path) != fixture_source:
                    raise ValueError(f"Changed fixture needs to bind the exact canonical source: {relative_path}")
            affected_ids.update(changed_fixture_sources)
        elif revision is not None:
            affected_ids.update(_previous_fixture_source_ids(revision, relative_path))
    current_fixture_ids = {extension_id for items in fixture_sources.values() for extension_id in items}
    for extension_id in sorted(affected_ids):
        path = ROOT / f"{SOURCE_PREFIX}{extension_id}.json"
        if not path.is_file():
            if extension_id in current_fixture_ids:
                raise ValueError(f"Portable fixture has no canonical source: {extension_id}")
            continue
        source = _load_object(path)
        if _extension_id(source, path) != extension_id:
            raise ValueError(f"Source identity does not match its canonical filename: {_relative(path)}")
        if not any(items.get(extension_id) == source for items in fixture_sources.values()):
            raise ValueError(
                f"Changed source needs a matching portable fixture with the same build source: {_relative(path)}"
            )
    return fixture_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify projections without writing them.")
    parser.add_argument("--compiler", type=Path, help="Use an already-built native source compiler.")
    parser.add_argument(
        "--changed-from",
        help="Require every changed command source since this revision to have a matching portable fixture.",
    )
    parser.add_argument("--source", type=Path, help="One explicit command source to bind to --fixture.")
    parser.add_argument("--fixture", type=Path, help="One explicit portable fixture to bind to --source.")
    args = parser.parse_args(argv)
    try:
        if (args.source is None) != (args.fixture is None):
            raise ValueError("Use --source and --fixture together.")
        compiler = _compiler(args.compiler)
        fixture_paths = _fixtures()
        if args.source is not None:
            source = _load_object(args.source)
            extension_id = _extension_id(source, args.source)
            fixture = _load_object(args.fixture)
            if _fixture_source_ids(fixture, args.fixture).get(extension_id) != source:
                raise ValueError("The portable fixture does not bind the exact source document.")
            fixture_paths = [args.fixture]
        if args.changed_from:
            fixture_paths = _validate_changed_source_fixture_pairs(
                _changed_paths(args.changed_from), fixture_paths, revision=args.changed_from
            )
        validated = [_validate_fixture(compiler, path) for path in fixture_paths]
        projection = [
            sys.executable,
            str(ROOT / "scripts/build_native_command_program.py"),
            "--compiler",
            str(compiler),
        ]
        directory = [sys.executable, str(ROOT / "scripts/export_extension_directory.py")]
        if args.check:
            projection.append("--check")
            directory.append("--check")
        _ = _run(projection)
        _ = _run(directory)
        print(
            json.dumps(
                {
                    "ok": True,
                    "checked": bool(args.check),
                    "fixtures": validated,
                    "targetCommandsExecuted": 0,
                },
                sort_keys=True,
            )
        )
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
