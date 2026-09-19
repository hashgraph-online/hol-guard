"""Parse dependency changes from manifests and lockfiles."""

from __future__ import annotations

import importlib
import json
import re
import sys
import time
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

if TYPE_CHECKING or sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = importlib.import_module("tomli")

from .jsonc import loads_jsonc as loads_jsonc
from .package_intent_common import (
    ManifestDependencyChange,
    ManifestParseResult,
    PackageIntentTarget,
    python_target,
)
from .package_manifest_js import (
    _bun_lock_dependency_map as _bun_lock_dependency_map,
)
from .package_manifest_js import (
    _bun_lock_package_versions as _bun_lock_package_versions,
)
from .package_manifest_js import (
    _bun_resolution_identity as _bun_resolution_identity,
)
from .package_manifest_js import (
    _exact_dependency_version as _exact_dependency_version,
)
from .package_manifest_js import (
    _json_dependency_map as _json_dependency_map,
)
from .package_manifest_js import (
    _package_lock_dependency_map as _package_lock_dependency_map,
)
from .package_manifest_js import (
    _pnpm_entry_name_version as _pnpm_entry_name_version,
)
from .package_manifest_js import (
    _pnpm_lock_dependency_map as _pnpm_lock_dependency_map,
)
from .package_manifest_js import (
    _walk_package_lock_v1_dependencies as _walk_package_lock_v1_dependencies,
)
from .package_manifest_js import (
    _yarn_lock_dependency_map as _yarn_lock_dependency_map,
)
from .package_manifest_js import (
    _yarn_selector_name as _yarn_selector_name,
)
from .package_manifest_js import (
    _yarn_selector_names as _yarn_selector_names,
)

_GRADLE_DEP_RE = re.compile(r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9+_.-]+)")
_GEMFILE_RE = re.compile(r"""gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""")
_GO_REQUIRE_RE = re.compile(r"^\s*([A-Za-z0-9./_-]+)\s+(v[^\s]+)\s*$")
_YARN_CLASSIC_VERSION_RE = re.compile(r'^version\s+"([^"]+)"$')
_YARN_BERRY_VERSION_RE = re.compile(r'^version:\s*"?([^"\s]+)"?$')


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


def parse_manifest_dependencies(
    *,
    path: str,
    text: str,
    byte_limit: int = 2_097_152,
    deadline_ms: int = 50,
) -> dict[str, str]:
    if len(text.encode("utf-8")) > byte_limit:
        return {}
    deadline = time.monotonic() + (deadline_ms / 1000)
    try:
        return _dependency_map_for_path(path, text, deadline=deadline)
    except Exception:
        return {}


def _dependency_map_for_path(
    path: str, text: str, *, deadline: float, document: dict[str, object] | None = None
) -> dict[str, str]:
    lower_path = path.lower()
    lower_name = lower_path.rsplit("/", 1)[-1]
    if lower_path.endswith("package.json"):
        return _json_dependency_map(
            text,
            ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"),
            deadline,
        )
    if lower_path.endswith("package-lock.json"):
        return _package_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("pnpm-lock.yaml"):
        return _pnpm_lock_dependency_map(text, deadline)
    if lower_path.endswith("yarn.lock"):
        return _yarn_lock_dependency_map(text, deadline)
    if lower_path.endswith("bun.lock"):
        return _bun_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("composer.json"):
        return _json_dependency_map(text, ("require", "require-dev"), deadline)
    if (
        lower_path.endswith("requirements.txt")
        or lower_path.endswith("constraints.txt")
        or lower_name.endswith(".requirements.txt")
    ):
        return _requirements_dependency_map(text, deadline)
    if lower_path.endswith("pyproject.toml"):
        return _pyproject_dependency_map(text, deadline)
    if lower_path.endswith("poetry.lock"):
        return _poetry_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("uv.lock"):
        return _uv_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("pipfile"):
        return _toml_table_dependency_map(text, ("packages", "dev-packages"), deadline)
    if lower_path.endswith("pipfile.lock"):
        return _pipfile_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("cargo.toml"):
        return _cargo_toml_dependency_map(text, deadline)
    if lower_path.endswith("cargo.lock"):
        return _cargo_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("go.mod"):
        return _go_mod_dependency_map(text, deadline)
    if lower_path.endswith("pom.xml"):
        return _pom_dependency_map(text, deadline)
    if lower_path.endswith("build.gradle") or lower_path.endswith("build.gradle.kts"):
        return _gradle_dependency_map(text, deadline)
    if lower_path.endswith("gradle.lockfile"):
        return _gradle_lockfile_dependency_map(text, deadline)
    if lower_path.endswith("composer.lock"):
        return _composer_lock_dependency_map(text, deadline, document=document)
    if lower_path.endswith("gemfile"):
        return _gemfile_dependency_map(text, deadline)
    if lower_path.endswith("gemfile.lock"):
        return _gemfile_lock_dependency_map(text, deadline)
    return {}


def _requirements_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in _requirements_logical_lines(text, deadline):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        stripped = re.split(r"\s+#", stripped, maxsplit=1)[0].strip()
        stripped = re.sub(r"\s+--hash(?:=|\s+)[^\s]+", "", stripped).strip()
        if not stripped or stripped.startswith("-"):
            continue
        target: PackageIntentTarget = python_target(stripped)
        if target.package_name is not None:
            dependencies[target.package_name] = target.requested_specifier or ""
    return dependencies


def _requirements_logical_lines(text: str, deadline: float) -> list[str]:
    logical_lines: list[str] = []
    current = ""
    for line in text.splitlines():
        _ensure_within_deadline(deadline)
        fragment = line.rstrip()
        if current:
            fragment = f"{current} {fragment.lstrip()}"
        if fragment.endswith("\\"):
            current = fragment[:-1].rstrip()
            continue
        logical_lines.append(fragment)
        current = ""
    if current:
        logical_lines.append(current)
    return logical_lines


def _pyproject_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
    dependencies: dict[str, str] = {}
    project = payload.get("project")
    if isinstance(project, dict):
        _collect_python_dependency_list(dependencies, project.get("dependencies"), deadline)
        optional_dependencies = project.get("optional-dependencies")
        if isinstance(optional_dependencies, dict):
            for values in optional_dependencies.values():
                _collect_python_dependency_list(dependencies, values, deadline)
    tool = payload.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            _collect_poetry_dependency_table(dependencies, poetry.get("dependencies"), deadline)
            _collect_poetry_dependency_table(dependencies, poetry.get("dev-dependencies"), deadline)
            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group in groups.values():
                    if not isinstance(group, dict):
                        continue
                    _collect_poetry_dependency_table(dependencies, group.get("dependencies"), deadline)
    return dependencies


def _collect_python_dependency_list(
    dependencies: dict[str, str],
    values: object,
    deadline: float,
) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        _ensure_within_deadline(deadline)
        target = python_target(str(value))
        if target.package_name is not None:
            dependencies[target.package_name] = target.requested_specifier or ""


def _collect_poetry_dependency_table(
    dependencies: dict[str, str],
    values: object,
    deadline: float,
) -> None:
    if not isinstance(values, dict):
        return
    for package_name, value in values.items():
        _ensure_within_deadline(deadline)
        normalized_name = str(package_name)
        if normalized_name == "python":
            continue
        if isinstance(value, str):
            dependencies[normalized_name] = value
            continue
        if isinstance(value, dict) and isinstance(value.get("version"), str):
            dependencies[normalized_name] = str(value["version"])


def _toml_lock_dependency_map(
    text: str, deadline: float, *, document: dict[str, object] | None = None
) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "") if document is None else document
    packages = payload.get("package")
    dependencies: dict[str, str] = {}
    if not isinstance(packages, list):
        return dependencies
    for package in packages:
        _ensure_within_deadline(deadline)
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            dependencies[name] = version
    return dependencies


_poetry_lock_dependency_map = _toml_lock_dependency_map
_uv_lock_dependency_map = _toml_lock_dependency_map
_cargo_lock_dependency_map = _toml_lock_dependency_map


def _pipfile_lock_dependency_map(
    text: str, deadline: float, *, document: dict[str, object] | None = None
) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = json.loads(text or "{}") if document is None else document
    dependencies: dict[str, str] = {}
    for section in ("default", "develop"):
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for package_name, package_value in values.items():
            _ensure_within_deadline(deadline)
            if not isinstance(package_name, str) or not isinstance(package_value, dict):
                continue
            exact_version = _exact_dependency_version(package_value.get("version"))
            if exact_version is not None:
                dependencies[package_name] = exact_version
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


def _cargo_toml_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
    dependencies: dict[str, str] = {}
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        _collect_toml_dependency_table(dependencies, payload.get(section), deadline)
    workspace = payload.get("workspace")
    if isinstance(workspace, dict):
        _collect_toml_dependency_table(dependencies, workspace.get("dependencies"), deadline)
    target = payload.get("target")
    if isinstance(target, dict):
        for section_payload in target.values():
            _ensure_within_deadline(deadline)
            if not isinstance(section_payload, dict):
                continue
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                _collect_toml_dependency_table(dependencies, section_payload.get(section), deadline)
    return dependencies


def _collect_toml_dependency_table(
    dependencies: dict[str, str],
    values: object,
    deadline: float,
) -> None:
    if not isinstance(values, dict):
        return
    for package_name, value in values.items():
        _ensure_within_deadline(deadline)
        if isinstance(value, str):
            dependencies[str(package_name)] = value
            continue
        if isinstance(value, dict) and isinstance(value.get("version"), str):
            dependencies[str(package_name)] = str(value["version"])


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


def _gradle_lockfile_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for raw_line in text.splitlines():
        _ensure_within_deadline(deadline)
        line = raw_line.strip()
        if not line or line.startswith(("#", "empty=")) or "=" not in line:
            continue
        package_name, _, version = line.rpartition(":")
        if package_name and version:
            dependencies[package_name] = version
    return dependencies


def _composer_lock_dependency_map(
    text: str, deadline: float, *, document: dict[str, object] | None = None
) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = json.loads(text or "{}") if document is None else document
    dependencies: dict[str, str] = {}
    for section in ("packages", "packages-dev"):
        packages = payload.get(section)
        if not isinstance(packages, list):
            continue
        for package in packages:
            _ensure_within_deadline(deadline)
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                dependencies[name] = version
    return dependencies


def _gemfile_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in text.splitlines():
        _ensure_within_deadline(deadline)
        match = _GEMFILE_RE.search(line)
        if match is not None:
            dependencies[match.group(1)] = match.group(2) or ""
    return dependencies


def _gemfile_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    in_specs_block = False
    for raw_line in text.splitlines():
        _ensure_within_deadline(deadline)
        stripped = raw_line.strip()
        if stripped == "specs:":
            in_specs_block = True
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9_ ]+", stripped or ""):
            in_specs_block = False
            continue
        if not in_specs_block:
            continue
        match = re.match(r"^\s{4}([A-Za-z0-9_.:-]+) \(([^)]+)\)", raw_line)
        if match is not None:
            dependencies[match.group(1)] = match.group(2)
    return dependencies


def _ensure_within_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _DeadlineExceededError("deadline_exceeded")
