"""Single traversal of the existing bounded Yarn, pnpm and Bundler grammar.

This is the existing supported text projection, not a new general YAML parser.
Validation, transitive entries and direct-selector data consume the same lines.
The immutable projection retains declaration order and distinct selector views.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from .package_lock_versions import direct_lockfile_version
from .package_manifest_diff import (
    _DeadlineExceededError,
    _exact_dependency_version,
    _pnpm_entry_name_version,
    _yarn_selector_name,
)

_YARN_CLASSIC_VERSION_RE = re.compile(r'^version\s+"([^"]+)"$')
_YARN_BERRY_VERSION_RE = re.compile(r'^version:\s*"?([^"\s]+)"?$')
_GEM_SECTION_RE = re.compile(r"[A-Z][A-Z0-9_ ]+")
_GEM_ENTRY_RE = re.compile(r"^\s{4}([A-Za-z0-9_.:-]+) \(([^)]+)\)")


class TextLockfileValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TextLockfileProjection:
    dependencies: tuple[tuple[str, str], ...]
    direct_versions: tuple[tuple[str, str], ...] = ()
    yarn_selector_versions: tuple[tuple[tuple[str, ...], str], ...] = ()


class _PnpmProjection:
    def __init__(self) -> None:
        self.dependencies: dict[str, str] = {}
        self.package_versions: dict[str, str] = {}
        self.direct_versions: dict[str, str] = {}
        self.section: str | None = None
        self.snapshot_dependencies = False
        self.importer: str | None = None
        self.dependency_block: str | None = None
        self.dependency_name: str | None = None

    def consume(self, raw_line: str, stripped: str) -> None:
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            self.section = stripped.removesuffix(":")
            self.snapshot_dependencies = False
            self.importer = self.dependency_block = self.dependency_name = None
            return
        if self.section in {"packages", "snapshots"}:
            self._transitive(indent, stripped)
        elif self.section in {"dependencies", "devDependencies", "optionalDependencies"}:
            self._direct(indent, stripped, name_indent=2)
        elif self.section == "importers":
            if indent == 2 and stripped.endswith(":"):
                self.importer = stripped[:-1].strip('"').strip("'")
                self.dependency_block = self.dependency_name = None
            elif self.importer in {".", "default"}:
                if indent == 4 and stripped.endswith(":"):
                    block = stripped.removesuffix(":")
                    self.dependency_block = block if "dependencies" in block.lower() else None
                    self.dependency_name = None
                elif self.dependency_block is not None:
                    self._direct(indent, stripped, name_indent=6)

    def _transitive(self, indent: int, stripped: str) -> None:
        if indent == 2 and stripped.endswith(":"):
            self.snapshot_dependencies = False
            name, version = _pnpm_entry_name_version(stripped[:-1].strip().strip('"').strip("'"))
            if name is not None and version is not None:
                self.package_versions[name] = self.dependencies[name] = version
            return
        if self.section == "snapshots" and indent == 4 and stripped == "dependencies:":
            self.snapshot_dependencies = True
            return
        if self.section == "snapshots" and indent <= 4:
            self.snapshot_dependencies = False
        if not self.snapshot_dependencies or indent < 6 or ":" not in stripped:
            return
        name, _, value = stripped.partition(":")
        name, value = name.strip().strip('"').strip("'"), value.strip().strip('"').strip("'")
        version = self.package_versions.get(name) or _exact_dependency_version(value)
        if version is not None:
            self.dependencies[name] = version

    def _direct(self, indent: int, stripped: str, *, name_indent: int) -> None:
        if indent == name_indent and ":" in stripped:
            name, _, value = stripped.partition(":")
            self.dependency_name = name.strip().strip('"').strip("'")
            version = direct_lockfile_version(value.strip().strip('"').strip("'"))
            if version is not None:
                self.direct_versions[self.dependency_name] = version
                self.dependency_name = None
        elif self.dependency_name is not None and indent >= name_indent + 2 and stripped.startswith("version:"):
            version = direct_lockfile_version(stripped.partition(":")[2].strip().strip('"').strip("'"))
            if version is not None:
                self.direct_versions[self.dependency_name] = version
            self.dependency_name = None


def _yarn_header_projection(
    header: str, *, deadline: float, max_entries: int
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    names: dict[str, None] = {}
    selectors: list[str] = []
    # Avoid an unbounded split list and quadratic list-membership deduplication.
    # In particular, versionless headers must obey limits before any next line.
    start = 0
    while start <= len(header):
        if time.monotonic() > deadline:
            raise _DeadlineExceededError("deadline_exceeded")
        end = header.find(",", start)
        part = header[start:] if end < 0 else header[start:end]
        selector = part.strip().strip('"').strip("'")
        if selector and selector != "__metadata":
            selectors.append(selector)
            if len(selectors) > max_entries:
                raise TextLockfileValidationError("entry_limit_exceeded")
            name = _yarn_selector_name(selector)
            if name:
                names.setdefault(name, None)
        if end < 0:
            break
        start = end + 1
    return tuple(names), tuple(selectors)


def parse_text_lockfile(name: str, text: str, *, deadline: float, max_entries: int) -> TextLockfileProjection:
    """Validate each line and collect all supported views before publishing any."""

    dependencies: dict[str, str] = {}
    pnpm = _PnpmProjection() if name == "pnpm-lock.yaml" else None
    selectors: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    yarn_versions: list[tuple[tuple[str, ...], str]] = []
    selector_count = 0
    declared_selectors = 0
    in_specs = False
    bracket_depth = 0
    for raw_line in text.splitlines():
        if time.monotonic() > deadline:
            raise _DeadlineExceededError("deadline_exceeded")
        if "\x00" in raw_line or ("\t" in raw_line and name == "pnpm-lock.yaml"):
            raise TextLockfileValidationError("syntax_error")
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        bracket_depth += raw_line.count("[") + raw_line.count("{")
        bracket_depth -= raw_line.count("]") + raw_line.count("}")
        if bracket_depth < 0:
            raise TextLockfileValidationError("syntax_error")
        if pnpm is not None:
            if ":" not in stripped and not stripped.startswith("-"):
                raise TextLockfileValidationError("syntax_error")
            pnpm.consume(raw_line, stripped)
            dependencies = pnpm.dependencies
        elif name == "yarn.lock":
            if not raw_line.startswith((" ", "\t")):
                if not stripped.endswith(":"):
                    raise TextLockfileValidationError("syntax_error")
                header = stripped.removesuffix(":")
                names, selectors = _yarn_header_projection(
                    header, deadline=deadline, max_entries=max_entries - declared_selectors
                )
                declared_selectors += len(selectors)
            elif names or selectors:
                match = _YARN_CLASSIC_VERSION_RE.match(stripped) or _YARN_BERRY_VERSION_RE.match(stripped)
                if match is not None:
                    version = match.group(1)
                    for package_name in names:
                        dependencies[package_name] = version
                    if selectors:
                        selector_count += len(selectors)
                        yarn_versions.append((selectors, version))
        else:
            if stripped == "specs:":
                in_specs = True
            elif _GEM_SECTION_RE.fullmatch(stripped):
                in_specs = False
            elif in_specs and (match := _GEM_ENTRY_RE.match(raw_line)) is not None:
                dependencies[match.group(1)] = match.group(2)
        if (
            len(dependencies) > max_entries
            or (pnpm is not None and len(pnpm.direct_versions) > max_entries)
            or selector_count > max_entries
        ):
            raise TextLockfileValidationError("entry_limit_exceeded")
    if bracket_depth != 0:
        raise TextLockfileValidationError("syntax_error")
    return TextLockfileProjection(
        dependencies=tuple(dependencies.items()),
        direct_versions=tuple(pnpm.direct_versions.items()) if pnpm is not None else (),
        yarn_selector_versions=tuple(yarn_versions),
    )
