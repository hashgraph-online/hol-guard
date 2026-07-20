"""Evaluator-neutral lockfile collection and incomplete-result helpers."""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from .lockfile_parse_result import (
    DependencyMapParser,
    LockfileParseResult,
    PackageLockParser,
    incomplete_lockfile_result,
    parse_lockfile_text,
)
from .workspace_path_guard import read_bytes_within_workspace, resolve_path_within_workspace


class LockfileTextParser(Protocol):
    def __call__(self, path: str, text: str) -> LockfileParseResult: ...


def collect_lockfile_parse_results(
    workspace_dir: Path | None,
    lockfile_paths: object,
    *,
    budget_ms: float,
    parse_text_result: LockfileTextParser,
) -> tuple[LockfileParseResult, ...]:
    """Parse every supported workspace lockfile without returning partial data."""

    if workspace_dir is None or not isinstance(lockfile_paths, list):
        return ()
    results: list[LockfileParseResult] = []
    for relative_path_value in cast("list[object]", lockfile_paths):
        relative_path = str(relative_path_value)
        lockfile_path = resolve_path_within_workspace(workspace_dir, relative_path)
        if lockfile_path is None:
            results.append(
                incomplete_lockfile_result(
                    relative_path,
                    b"",
                    error_reason="traversal_error",
                    budget_ms=budget_ms,
                )
            )
            continue
        if not lockfile_path.exists() or lockfile_path.name.lower() == "bun.lockb":
            continue
        lockfile_bytes = read_bytes_within_workspace(workspace_dir, relative_path)
        if lockfile_bytes is None:
            results.append(
                incomplete_lockfile_result(
                    lockfile_path.name,
                    b"",
                    error_reason="read_error",
                    budget_ms=budget_ms,
                )
            )
            continue
        try:
            lockfile_text = lockfile_bytes.decode("utf-8")
        except UnicodeDecodeError:
            results.append(
                incomplete_lockfile_result(
                    lockfile_path.name,
                    lockfile_bytes,
                    error_reason="decode_error",
                    budget_ms=budget_ms,
                )
            )
            continue
        results.append(
            parse_text_result(lockfile_path.name, lockfile_text)
        )
    return tuple(results)


def parse_lockfile_with_budget(
    path: str,
    text: str,
    *,
    budget_seconds: float,
    dependency_parser: DependencyMapParser,
    package_lock_parser: PackageLockParser,
) -> LockfileParseResult:
    budget_ms = budget_seconds * 1000
    return parse_lockfile_text(
        path,
        text,
        deadline=time.monotonic() + budget_seconds,
        budget_ms=budget_ms,
        dependency_parser=dependency_parser,
        package_lock_parser=package_lock_parser,
    )


def incomplete_lockfile_metadata(parse_result: LockfileParseResult) -> dict[str, object]:
    return {
        "lockfileHash": parse_result.source_hash,
        "lockfileParserVersion": parse_result.parser_version,
        "lockfileFormat": parse_result.format,
        "lockfileParseComplete": False,
        "lockfileParseError": parse_result.error_reason or "parse_error",
        "lockfileParseElapsedMs": round(parse_result.elapsed_ms, 3),
        "lockfileParseBudgetMs": parse_result.budget_ms,
        "lockfileParseWarnings": list(parse_result.warnings),
    }


def incomplete_lockfile_fallback_target(parse_result: LockfileParseResult) -> dict[str, object]:
    ecosystem = {
        "bundler-lock": "rubygems",
        "cargo-lock": "cargo",
        "composer-lock": "composer",
        "pipenv-lock": "pypi",
        "poetry-lock": "pypi",
        "uv-lock": "pypi",
    }.get(parse_result.format, "npm")
    package_manager = {
        "bundler-lock": "bundler",
        "cargo-lock": "cargo",
        "composer-lock": "composer",
        "pipenv-lock": "pipenv",
        "poetry-lock": "poetry",
        "uv-lock": "uv",
    }.get(parse_result.format, "npm")
    return {
        "ecosystem": ecosystem,
        "name": "unresolved-lockfile",
        "namespace": None,
        "package_manager": package_manager,
        "range": None,
        "version": None,
        "redacted_command": None,
        "alias": None,
    }


def package_has_incomplete_lockfile(package: Mapping[str, object]) -> bool:
    if package.get("lockfileParseComplete") is False:
        return True
    reasons = package.get("reasons")
    if not isinstance(reasons, (list, tuple)):
        return False
    for reason in cast("list[object] | tuple[object, ...]", reasons):
        if isinstance(reason, Mapping) and cast("Mapping[object, object]", reason).get("code") == (
            "lockfile_parse_incomplete"
        ):
            return True
    return False
