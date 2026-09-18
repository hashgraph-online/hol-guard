"""Complete-or-fail lockfile parsing contract and resource bounds."""

from __future__ import annotations

import importlib
import json
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from ..stable_digest import stable_digest_hex
from .jsonc import loads_jsonc
from .lockfile_text_projection import TextLockfileValidationError, parse_text_lockfile
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
    manifest_dependencies: tuple[tuple[str, str], ...] | None = None
    direct_version_candidates: tuple[tuple[str, str], ...] = ()
    yarn_selector_versions: tuple[tuple[tuple[str, ...], str], ...] = ()
    source_hash_complete: bool = True
    source_byte_count: int | None = None
    source_byte_limit: int | None = None

    def dependency_map(self) -> dict[str, str]:
        if not self.complete:
            return {}
        return {entry.dependency_path: entry.version for entry in self.entries}

    def manifest_dependency_map(self) -> dict[str, str]:
        if not self.complete:
            return {}
        if self.manifest_dependencies is not None:
            return dict(self.manifest_dependencies)
        return self.dependency_map()


class DependencyMapParser(Protocol):
    def __call__(
        self, path: str, text: str, *, deadline: float, document: dict[str, object] | None = None
    ) -> dict[str, str]: ...


class PackageLockParser(Protocol):
    def __call__(
        self,
        text: str,
        *,
        deadline: float | None = None,
        document: dict[str, object] | None = None,
    ) -> list[tuple[str, str, str, bool]]: ...


class _LockfileValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def incomplete_lockfile_result(
    path: str,
    source: bytes,
    *,
    error_reason: str,
    budget_ms: float,
    elapsed_ms: float = 0.0,
    source_hash: str | None = None,
    source_hash_complete: bool = True,
    source_byte_count: int | None = None,
    source_byte_limit: int | None = None,
) -> LockfileParseResult:
    return LockfileParseResult(
        entries=(),
        complete=False,
        format=_lockfile_format(path),
        source_hash=stable_digest_hex(source) if source_hash is None else source_hash,
        elapsed_ms=elapsed_ms,
        budget_ms=budget_ms,
        error_reason=error_reason,
        source_hash_complete=source_hash_complete,
        source_byte_count=source_byte_count,
        source_byte_limit=source_byte_limit,
        warnings=() if source_hash_complete else ("source_hash_unavailable",),
    )


def parse_lockfile_text(
    path: str,
    source_text: str | bytes,
    *,
    deadline: float,
    budget_ms: float,
    dependency_parser: DependencyMapParser,
    package_lock_parser: PackageLockParser,
) -> LockfileParseResult:
    started = time.monotonic()
    source = b""
    lockfile_format = _lockfile_format(path)
    try:
        source = source_text if isinstance(source_text, bytes) else source_text.encode("utf-8")
        _ensure_within_deadline(deadline)
        if len(source) > LOCKFILE_MAX_BYTES:
            raise _LockfileValidationError("byte_limit_exceeded")
        text = source.decode("utf-8") if isinstance(source_text, bytes) else source_text
        lower_name = path.rsplit("/", 1)[-1].lower()
        if lower_name not in _JSON_LOCKFILES | _JSONC_LOCKFILES | _TOML_LOCKFILES | _TEXT_LOCKFILES:
            raise _LockfileValidationError("unsupported_format")
        document = (
            None if lower_name in _TEXT_LOCKFILES else _validate_lockfile_structure(lower_name, text, deadline=deadline)
        )
        manifest_dependencies = None
        direct_version_candidates = ()
        yarn_selector_versions = ()
        if lower_name in _TEXT_LOCKFILES:
            projection = parse_text_lockfile(lower_name, text, deadline=deadline, max_entries=LOCKFILE_MAX_ENTRIES)
            entries = tuple(
                LockfileDependencyEntry(package_name, package_name, version, False)
                for package_name, version in projection.dependencies
            )
            direct_version_candidates = projection.direct_versions
            yarn_selector_versions = projection.yarn_selector_versions
        elif lower_name == "package-lock.json":
            raw_entries = package_lock_parser(text, deadline=deadline, document=document)
            entries = tuple(LockfileDependencyEntry(*entry) for entry in raw_entries)
            # The manifest resolver retains its legacy empty-packages fallback.
            # Both extraction views consume the same validated JSON document.
            manifest_dependencies = tuple(dependency_parser(path, text, deadline=deadline, document=document).items())
        else:
            dependency_map = dependency_parser(path, text, deadline=deadline, document=document)
            entries = tuple(
                LockfileDependencyEntry(
                    dependency_path=package_name,
                    package_name=package_name,
                    version=version,
                    direct=False,
                )
                for package_name, version in dependency_map.items()
            )
        _ensure_within_deadline(deadline)
        if len(entries) > LOCKFILE_MAX_ENTRIES or (
            manifest_dependencies is not None and len(manifest_dependencies) > LOCKFILE_MAX_ENTRIES
        ):
            raise _LockfileValidationError("entry_limit_exceeded")
        if lower_name not in _TEXT_LOCKFILES:
            direct_version_candidates = _direct_version_candidates(lower_name, document, deadline=deadline)
        if len(direct_version_candidates) > LOCKFILE_MAX_ENTRIES:
            raise _LockfileValidationError("entry_limit_exceeded")
        _ensure_within_deadline(deadline)
        return LockfileParseResult(
            entries=entries,
            complete=True,
            format=lockfile_format,
            source_hash=stable_digest_hex(source),
            elapsed_ms=(time.monotonic() - started) * 1000,
            budget_ms=budget_ms,
            manifest_dependencies=manifest_dependencies,
            direct_version_candidates=direct_version_candidates,
            yarn_selector_versions=yarn_selector_versions,
        )
    except _DeadlineExceededError:
        error_reason = "deadline_exceeded"
    except (_LockfileValidationError, TextLockfileValidationError) as exc:
        error_reason = exc.reason
    except (json.JSONDecodeError, tomllib.TOMLDecodeError):
        error_reason = "syntax_error"
    except UnicodeDecodeError:
        error_reason = "decode_error"
    except (MemoryError, RecursionError):
        error_reason = "resource_limit_exceeded"
    except (TypeError, UnicodeError, ValueError):
        error_reason = "parse_error"
    except Exception:
        # Dependency parsers are pluggable; any unexpected parser failure must fail closed.
        error_reason = "parse_error"
    return incomplete_lockfile_result(
        path,
        source,
        error_reason=error_reason,
        budget_ms=budget_ms,
        elapsed_ms=(time.monotonic() - started) * 1000,
    )


def _lockfile_format(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    return _LOCKFILE_FORMAT_MAP.get(name, "unknown")


def _direct_version_candidates(
    name: str, document: dict[str, object] | None, *, deadline: float
) -> tuple[tuple[str, str], ...]:
    """Keep Python direct-selector input order without retaining a mutable parse tree."""

    if document is None:
        return ()
    pairs: list[tuple[str, str]] = []
    if name in {"poetry.lock", "uv.lock"}:
        packages = document.get("package")
        for package in packages if isinstance(packages, list) else ():
            _ensure_within_deadline(deadline)
            if isinstance(package, dict):
                package_name, version = package.get("name"), package.get("version")
                if isinstance(package_name, str) and isinstance(version, str):
                    pairs.append((package_name, version))
    elif name == "pipfile.lock":
        for section in ("default", "develop"):
            packages = document.get(section)
            for package_name, package in packages.items() if isinstance(packages, dict) else ():
                _ensure_within_deadline(deadline)
                version = package.get("version") if isinstance(package, dict) else None
                if isinstance(package_name, str) and isinstance(version, str):
                    pairs.append((package_name, version))
    return tuple(pairs)


def _ensure_within_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _DeadlineExceededError("deadline_exceeded")


def _validate_lockfile_structure(name: str, text: str, *, deadline: float) -> dict[str, object] | None:
    if name in _JSON_LOCKFILES:
        payload = json.loads(text or "{}", object_pairs_hook=_unique_object)
        _validate_object_bounds(payload, deadline=deadline)
        if not isinstance(payload, dict):
            raise _LockfileValidationError("unsupported_shape")
        if name == "package-lock.json":
            _validate_package_lock(payload)
        elif name == "composer.lock":
            _validate_optional_lists(payload, ("packages", "packages-dev"))
        else:
            _validate_optional_mappings(payload, ("default", "develop"))
        return payload
    if name in _JSONC_LOCKFILES:
        payload = loads_jsonc(
            text or "{}",
            object_pairs_hook=_unique_object,
            deadline_check=lambda: _ensure_within_deadline(deadline),
        )
        _validate_object_bounds(payload, deadline=deadline)
        if not isinstance(payload, dict):
            raise _LockfileValidationError("unsupported_shape")
        _validate_bun_lock(payload)
        return payload
    if name in _TOML_LOCKFILES:
        payload = tomllib.loads(text or "")
        _validate_object_bounds(payload, deadline=deadline)
        if not isinstance(payload, dict):
            raise _LockfileValidationError("unsupported_shape")
        packages = payload.get("package")
        if packages is not None and not isinstance(packages, list):
            raise _LockfileValidationError("unsupported_shape")
        return payload
    raise _LockfileValidationError("unsupported_format")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise _LockfileValidationError("duplicate_key")
        payload[key] = value
    return payload


def _validate_object_bounds(payload: object, *, deadline: float) -> None:
    stack: list[tuple[object, int]] = [(payload, 0)]
    visited = 0
    while stack:
        _ensure_within_deadline(deadline)
        value, depth = stack.pop()
        visited += 1
        if visited > LOCKFILE_MAX_NODES:
            raise _LockfileValidationError("node_limit_exceeded")
        if depth > LOCKFILE_MAX_DEPTH:
            raise _LockfileValidationError("depth_limit_exceeded")
        next_depth = depth + 1
        if isinstance(value, dict):
            stack.extend([(item, next_depth) for item in value.values()])
        elif isinstance(value, list):
            stack.extend([(item, next_depth) for item in value])


def _validate_package_lock(payload: dict[str, object]) -> None:
    version = payload.get("lockfileVersion")
    if version is not None and (isinstance(version, bool) or version not in {1, 2, 3}):
        raise _LockfileValidationError("unsupported_version")
    _validate_optional_mappings(payload, ("packages", "dependencies"))


def _validate_bun_lock(payload: dict[str, object]) -> None:
    version = payload.get("lockfileVersion")
    if version is not None and (isinstance(version, bool) or version not in {0, 1, 2}):
        raise _LockfileValidationError("unsupported_version")
    _validate_optional_mappings(payload, ("workspaces", "packages"))


def _validate_optional_mappings(payload: dict[str, object], keys: tuple[str, ...]) -> None:
    for key in keys:
        if key in payload and not isinstance(payload[key], dict):
            raise _LockfileValidationError("unsupported_shape")


def _validate_optional_lists(payload: dict[str, object], keys: tuple[str, ...]) -> None:
    for key in keys:
        if key in payload and not isinstance(payload[key], list):
            raise _LockfileValidationError("unsupported_shape")
