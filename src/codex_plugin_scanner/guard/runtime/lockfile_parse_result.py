"""Complete-or-fail lockfile parsing contract and resource bounds."""

from __future__ import annotations

import importlib
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .package_manifest_diff import _DeadlineExceededError

if TYPE_CHECKING or sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 runtime compatibility
    tomllib = importlib.import_module("tomli")

LOCKFILE_PARSER_VERSION = "complete-v1"
LOCKFILE_MAX_BYTES = 8 * 1024 * 1024
LOCKFILE_MAX_ENTRIES = 100_000
LOCKFILE_MAX_NODES = 250_000
LOCKFILE_MAX_DEPTH = 128

_JSON_LOCKFILES = {"package-lock.json", "composer.lock", "pipfile.lock"}
_JSONC_LOCKFILES = {"bun.lock"}
_TOML_LOCKFILES = {"cargo.lock", "poetry.lock", "uv.lock"}
_TEXT_LOCKFILES = {"gemfile.lock", "pnpm-lock.yaml", "yarn.lock"}
_LOCKFILE_FORMAT_MAP = {
    "package-lock.json": "npm-package-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "yarn.lock": "yarn-lock",
    "bun.lock": "bun-lock",
    "cargo.lock": "cargo-lock",
    "composer.lock": "composer-lock",
    "gemfile.lock": "bundler-lock",
    "poetry.lock": "poetry-lock",
    "uv.lock": "uv-lock",
    "pipfile.lock": "pipenv-lock",
}


@dataclass(frozen=True, slots=True)
class LockfileDependencyEntry:
    dependency_path: str
    package_name: str
    version: str
    direct: bool


@dataclass(frozen=True, slots=True)
class LockfileParseResult:
    entries: tuple[LockfileDependencyEntry, ...]
    complete: bool
    format: str
    source_hash: str
    elapsed_ms: float
    budget_ms: float
    warnings: tuple[str, ...] = ()
    error_reason: str | None = None
    parser_version: str = LOCKFILE_PARSER_VERSION

    def dependency_map(self) -> dict[str, str]:
        if not self.complete:
            return {}
        return {entry.dependency_path: entry.version for entry in self.entries}


class DependencyMapParser(Protocol):
    def __call__(self, path: str, text: str, *, deadline: float) -> dict[str, str]: ...


class PackageLockParser(Protocol):
    def __call__(
        self,
        text: str,
        *,
        deadline: float | None = None,
    ) -> list[tuple[str, str, str, bool]]: ...


class _LockfileValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _ensure_within_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _DeadlineExceededError("deadline_exceeded")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _LockfileValidationError("duplicate_key")
        payload[key] = value
    return payload
