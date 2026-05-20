"""Parse dependency changes from manifests and lockfiles."""

from __future__ import annotations

import json
import re
import time
from xml.etree import ElementTree as ET

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from .package_intent_common import (
    ManifestDependencyChange,
    ManifestParseResult,
    PackageIntentTarget,
    python_target,
)

_GRADLE_DEP_RE = re.compile(r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9+_.-]+)")
_GEMFILE_RE = re.compile(r"""gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""")
_GO_REQUIRE_RE = re.compile(r"^\s*([A-Za-z0-9./_-]+)\s+(v[^\s]+)\s*$")


class _DeadlineExceededError(RuntimeError):
    pass


def parse_manifest_dependency_changes(
    *,
    path: str,
    before_text: str | None,
    after_text: str | None,
    byte_limit: int = 2_097_152,
    deadline_ms: int = 50,
) -> ManifestParseResult:
    before_text = before_text or ""
    after_text = after_text or ""
    if len(before_text.encode("utf-8")) + len(after_text.encode("utf-8")) > byte_limit:
        return ManifestParseResult((), truncated=True, parse_errors=("byte_limit_exceeded",))
    deadline = time.monotonic() + (deadline_ms / 1000)
    try:
        before_deps = _dependency_map_for_path(path, before_text, deadline=deadline)
        after_deps = _dependency_map_for_path(path, after_text, deadline=deadline)
    except _DeadlineExceededError:
        return ManifestParseResult((), truncated=True, parse_errors=("deadline_exceeded",))
    except Exception:
        return ManifestParseResult((), parse_errors=("parse_error",))
    changes = tuple(
        ManifestDependencyChange(path, package_name, before_deps.get(package_name), after_deps.get(package_name))
        for package_name in sorted(set(before_deps) | set(after_deps))
        if before_deps.get(package_name) != after_deps.get(package_name)
    )
    return ManifestParseResult(changes)


def _dependency_map_for_path(path: str, text: str, *, deadline: float) -> dict[str, str]:
    lower_path = path.lower()
    if lower_path.endswith("package.json"):
        return _json_dependency_map(
            text,
            ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"),
            deadline,
        )
    if lower_path.endswith("package-lock.json"):
        return _package_lock_dependency_map(text, deadline)
    if lower_path.endswith("composer.json"):
        return _json_dependency_map(text, ("require", "require-dev"), deadline)
    if lower_path.endswith("requirements.txt"):
        return _requirements_dependency_map(text, deadline)
    if lower_path.endswith("pyproject.toml"):
        return _pyproject_dependency_map(text, deadline)
    if lower_path.endswith("cargo.toml"):
        return _toml_table_dependency_map(text, ("dependencies", "dev-dependencies", "build-dependencies"), deadline)
    if lower_path.endswith("go.mod"):
        return _go_mod_dependency_map(text, deadline)
    if lower_path.endswith("pom.xml"):
        return _pom_dependency_map(text, deadline)
    if lower_path.endswith("build.gradle") or lower_path.endswith("build.gradle.kts"):
        return _gradle_dependency_map(text, deadline)
    if lower_path.endswith("gemfile"):
        return _gemfile_dependency_map(text, deadline)
    return {}


def _json_dependency_map(text: str, sections: tuple[str, ...], deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = json.loads(text or "{}")
    dependencies: dict[str, str] = {}
    for section in sections:
        values = payload.get(section)
        if isinstance(values, dict):
            for package_name, version in values.items():
                if isinstance(version, str):
                    dependencies[str(package_name)] = version
    return dependencies


def _package_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    payload = json.loads(text or "{}")
    dependencies: dict[str, str] = {}
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, value in packages.items():
            _ensure_within_deadline(deadline)
            if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
                continue
            version = value.get("version") if isinstance(value, dict) else None
            if isinstance(version, str):
                dependencies[package_path.removeprefix("node_modules/")] = version
    return dependencies


def _requirements_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in text.splitlines():
        _ensure_within_deadline(deadline)
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        target: PackageIntentTarget = python_target(stripped)
        if target.package_name is not None:
            dependencies[target.package_name] = target.requested_specifier or ""
    return dependencies


def _pyproject_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
    dependencies: dict[str, str] = {}
    project = payload.get("project")
    if isinstance(project, dict):
        values = project.get("dependencies")
        if isinstance(values, list):
            for value in values:
                target = python_target(str(value))
                if target.package_name is not None:
                    dependencies[target.package_name] = target.requested_specifier or ""
    return dependencies


def _toml_table_dependency_map(text: str, sections: tuple[str, ...], deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
    dependencies: dict[str, str] = {}
    for section in sections:
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for package_name, value in values.items():
            _ensure_within_deadline(deadline)
            if isinstance(value, str):
                dependencies[str(package_name)] = value
            elif isinstance(value, dict) and isinstance(value.get("version"), str):
                dependencies[str(package_name)] = str(value["version"])
    return dependencies


def _go_mod_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    in_require_block = False
    for raw_line in text.splitlines():
        _ensure_within_deadline(deadline)
        line = raw_line.strip()
        if line.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        elif not in_require_block:
            continue
        match = _GO_REQUIRE_RE.match(line)
        if match is not None:
            dependencies[match.group(1)] = match.group(2)
    return dependencies


def _pom_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    root = ET.fromstring(text or "<project />")
    dependencies: dict[str, str] = {}
    for dependency in root.findall(".//{*}dependency"):
        _ensure_within_deadline(deadline)
        group_id = dependency.findtext("{*}groupId")
        artifact_id = dependency.findtext("{*}artifactId")
        version = dependency.findtext("{*}version")
        if group_id and artifact_id and version:
            dependencies[f"{group_id}:{artifact_id}"] = version
    return dependencies


def _gradle_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in text.splitlines():
        _ensure_within_deadline(deadline)
        for match in _GRADLE_DEP_RE.finditer(line):
            dependencies[f"{match.group(1)}:{match.group(2)}"] = match.group(3)
    return dependencies


def _gemfile_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in text.splitlines():
        _ensure_within_deadline(deadline)
        match = _GEMFILE_RE.search(line)
        if match is not None:
            dependencies[match.group(1)] = match.group(2) or ""
    return dependencies


def _ensure_within_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _DeadlineExceededError("deadline_exceeded")
