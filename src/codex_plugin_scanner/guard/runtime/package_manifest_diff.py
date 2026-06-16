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

from .package_intent_common import (
    ManifestDependencyChange,
    ManifestParseResult,
    PackageIntentTarget,
    python_target,
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


def _dependency_map_for_path(path: str, text: str, *, deadline: float) -> dict[str, str]:
    lower_path = path.lower()
    lower_name = lower_path.rsplit("/", 1)[-1]
    if lower_path.endswith("package.json"):
        return _json_dependency_map(
            text,
            ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"),
            deadline,
        )
    if lower_path.endswith("package-lock.json"):
        return _package_lock_dependency_map(text, deadline)
    if lower_path.endswith("pnpm-lock.yaml"):
        return _pnpm_lock_dependency_map(text, deadline)
    if lower_path.endswith("yarn.lock"):
        return _yarn_lock_dependency_map(text, deadline)
    if lower_path.endswith("bun.lock"):
        return _bun_lock_dependency_map(text, deadline)
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
        return _poetry_lock_dependency_map(text, deadline)
    if lower_path.endswith("uv.lock"):
        return _uv_lock_dependency_map(text, deadline)
    if lower_path.endswith("pipfile"):
        return _toml_table_dependency_map(text, ("packages", "dev-packages"), deadline)
    if lower_path.endswith("pipfile.lock"):
        return _pipfile_lock_dependency_map(text, deadline)
    if lower_path.endswith("cargo.toml"):
        return _cargo_toml_dependency_map(text, deadline)
    if lower_path.endswith("cargo.lock"):
        return _cargo_lock_dependency_map(text, deadline)
    if lower_path.endswith("go.mod"):
        return _go_mod_dependency_map(text, deadline)
    if lower_path.endswith("pom.xml"):
        return _pom_dependency_map(text, deadline)
    if lower_path.endswith("build.gradle") or lower_path.endswith("build.gradle.kts"):
        return _gradle_dependency_map(text, deadline)
    if lower_path.endswith("gradle.lockfile"):
        return _gradle_lockfile_dependency_map(text, deadline)
    if lower_path.endswith("composer.lock"):
        return _composer_lock_dependency_map(text, deadline)
    if lower_path.endswith("gemfile"):
        return _gemfile_dependency_map(text, deadline)
    if lower_path.endswith("gemfile.lock"):
        return _gemfile_lock_dependency_map(text, deadline)
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
    if dependencies:
        return dependencies
    legacy_dependencies = payload.get("dependencies")
    if isinstance(legacy_dependencies, dict):
        _walk_package_lock_v1_dependencies(legacy_dependencies, dependencies, deadline)
    return dependencies


def _walk_package_lock_v1_dependencies(
    payload: dict[str, object],
    dependencies: dict[str, str],
    deadline: float,
) -> None:
    for package_name, value in payload.items():
        _ensure_within_deadline(deadline)
        if not isinstance(package_name, str) or not isinstance(value, dict):
            continue
        version = value.get("version")
        if isinstance(version, str):
            dependencies[package_name] = version
        nested_dependencies = value.get("dependencies")
        if isinstance(nested_dependencies, dict):
            _walk_package_lock_v1_dependencies(nested_dependencies, dependencies, deadline)


def _pnpm_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    package_versions: dict[str, str] = {}
    section: str | None = None
    dependency_block = False
    for raw_line in text.splitlines():
        _ensure_within_deadline(deadline)
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            section = stripped.removesuffix(":")
            dependency_block = False
            continue
        if section not in {"packages", "snapshots"}:
            continue
        if indent == 2 and stripped.endswith(":"):
            dependency_block = False
            entry_name, entry_version = _pnpm_entry_name_version(stripped[:-1].strip().strip('"').strip("'"))
            if entry_name is not None and entry_version is not None:
                package_versions[entry_name] = entry_version
                dependencies[entry_name] = entry_version
            continue
        if section == "snapshots" and indent == 4 and stripped == "dependencies:":
            dependency_block = True
            continue
        if section == "snapshots" and indent <= 4:
            dependency_block = False
        if not dependency_block or indent < 6 or ":" not in stripped:
            continue
        dependency_name, _, dependency_value = stripped.partition(":")
        normalized_name = dependency_name.strip().strip('"').strip("'")
        normalized_value = dependency_value.strip().strip('"').strip("'")
        exact_version = package_versions.get(normalized_name) or _exact_dependency_version(normalized_value)
        if exact_version is not None:
            dependencies[normalized_name] = exact_version
    return dependencies


def _pnpm_entry_name_version(entry: str) -> tuple[str | None, str | None]:
    normalized_entry = entry.split("(", 1)[0].lstrip("/")
    if "@" not in normalized_entry:
        return None, None
    package_name, _, package_version = normalized_entry.rpartition("@")
    if not package_name or not package_version:
        return None, None
    return package_name, package_version


def _yarn_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    current_names: tuple[str, ...] = ()
    for raw_line in text.splitlines():
        _ensure_within_deadline(deadline)
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line.startswith((" ", "\t")):
            current_names = _yarn_selector_names(stripped.removesuffix(":"))
            continue
        if not current_names:
            continue
        version_match = _YARN_CLASSIC_VERSION_RE.match(stripped) or _YARN_BERRY_VERSION_RE.match(stripped)
        if version_match is None:
            continue
        version = version_match.group(1)
        for package_name in current_names:
            dependencies[package_name] = version
    return dependencies


def _yarn_selector_names(selector_line: str) -> tuple[str, ...]:
    names: list[str] = []
    for part in selector_line.split(","):
        selector = part.strip().strip('"').strip("'")
        if not selector or selector == "__metadata":
            continue
        package_name = _yarn_selector_name(selector)
        if package_name and package_name not in names:
            names.append(package_name)
    return tuple(names)


def _yarn_selector_name(selector: str) -> str | None:
    if "@npm:" in selector and not selector.startswith("@npm:"):
        return selector.partition("@npm:")[0] or None
    if selector.startswith("@"):
        package_name, _, _ = selector.rpartition("@")
        return package_name or selector
    package_name, _, _ = selector.partition("@")
    return package_name or selector


def _bun_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
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
        nested_dependencies = package.get("dependencies")
        if not isinstance(nested_dependencies, list):
            continue
        for dependency in nested_dependencies:
            if not isinstance(dependency, dict):
                continue
            dependency_name = dependency.get("name")
            exact_version = _exact_dependency_version(dependency.get("version"))
            if isinstance(dependency_name, str) and exact_version is not None:
                dependencies.setdefault(dependency_name, exact_version)
    return dependencies


def _exact_dependency_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().strip('"').strip("'")
    if not normalized:
        return None
    while normalized.startswith(("=", "^", "~", "v")):
        normalized = normalized[1:]
    return normalized or None


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


def _poetry_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
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


def _uv_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
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


def _pipfile_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = json.loads(text or "{}")
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


def _cargo_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = tomllib.loads(text or "")
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


def _composer_lock_dependency_map(text: str, deadline: float) -> dict[str, str]:
    _ensure_within_deadline(deadline)
    payload = json.loads(text or "{}")
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
