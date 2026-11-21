"""CycloneDX software bill of materials for the HOL Plugin Release workflow.

The SBOM lists the third-party packages a plugin release ships or starts:
the non-development entries of ``package-lock.json``, exact ``==`` pins in
``requirements*.txt`` files other than development ones, registry and git
packages in ``uv.lock``, and the packages its MCP servers launch through npx,
bunx, pnpx or uvx. Only the plugin folder itself is read; nested folders,
symbolic links and oversized files are skipped. The document carries no run
time, so it is identical for a given commit and the digest recorded in the
release evidence identifies it exactly.

Like the rest of the release workflow tooling, this runs once per release in
GitHub Actions and never in the Guard runtime, so it stays in Python.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
import uuid
from base64 import b64decode
from binascii import Error as BinasciiError
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import quote

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

SPEC_VERSION = "1.6"
MAX_COMPONENTS = 50_000
_MAX_FILE_BYTES = 32 * 1024 * 1024
_MAX_TEXT = 214
_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:(?:[;#\\]|--).*)?$"
)
_LAUNCH_RE = re.compile(r"^((?:@[^@/\s]+/)?[^@=<>!~\s\[]+)(?:\[[^\]]*\])?(?:(@|==)(.+)|[<>!~=].*)?$")
_NPM_EXACT_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PYPI_EXACT_RE = re.compile(r"^\d[0-9A-Za-z._+!-]*$")
_DEV_REQUIREMENTS = frozenset(
    {"dev", "develop", "development", "test", "tests", "testing", "lint", "docs", "doc", "ci", "typing"}
)
_NPM_LAUNCHERS = frozenset({"npx", "bunx", "pnpx"})
_LOCAL_UV_SOURCES = frozenset({"editable", "virtual", "directory", "path"})

Ecosystem = Literal["npm", "pypi"]
Scope = Literal["required", "optional"]


@dataclass(frozen=True)
class SbomComponent:
    ecosystem: Ecosystem
    name: str
    version: str | None
    scope: Scope
    sha512: str | None
    source: str
    vcs_url: str | None = None

    @property
    def purl(self) -> str:
        segments = "/".join(quote(part, safe="._-~") for part in self.name.split("/"))
        version = f"@{quote(self.version, safe='._-~')}" if self.version else ""
        # A git checkout is not the registry release of the same name and version.
        qualifier = f"?vcs_url={quote(self.vcs_url, safe='')}" if self.vcs_url else ""
        return f"pkg:{self.ecosystem}/{segments}{version}{qualifier}"


@dataclass(frozen=True)
class SbomSummary:
    format: Literal["CycloneDX"]
    spec_version: str
    sha256: str
    components: int


@dataclass(frozen=True)
class PluginReleaseSbom:
    document: str
    summary: SbomSummary


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value and len(value) <= _MAX_TEXT and value.isprintable() else None


def _read(path: Path) -> str | None:
    """A regular file directly in the plugin folder, or nothing."""

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _sha512(integrity: object) -> str | None:
    if not isinstance(integrity, str):
        return None
    for entry in integrity.split():
        if entry.startswith("sha512-"):
            try:
                digest = b64decode(entry.removeprefix("sha512-"), validate=True)
            except (BinasciiError, ValueError):
                return None
            return digest.hex() if len(digest) == 64 else None
    return None


def _npm_entry(name: str, entry: Mapping[str, object]) -> SbomComponent | None:
    if entry.get("dev") is True or entry.get("link") is True:
        return None
    version = _text(entry.get("version"))
    if version is None or _text(name) is None:
        return None
    optional = entry.get("optional") is True or entry.get("devOptional") is True
    return SbomComponent(
        ecosystem="npm",
        name=name,
        version=version,
        scope="optional" if optional else "required",
        sha512=_sha512(entry.get("integrity")),
        source="package-lock.json",
    )


def _npm_tree(dependencies: object) -> Iterable[SbomComponent]:
    """Lockfile version 1 nests dependencies under each package."""

    if not isinstance(dependencies, Mapping):
        return
    for name, entry in dependencies.items():
        if isinstance(name, str) and isinstance(entry, Mapping):
            component = _npm_entry(name, entry)
            if component is not None:
                yield component
            yield from _npm_tree(entry.get("dependencies"))


def npm_components(text: str) -> list[SbomComponent]:
    try:
        lock = json.loads(text)
    except ValueError:
        return []
    if not isinstance(lock, Mapping):
        return []
    packages = lock.get("packages")
    if not isinstance(packages, Mapping):
        return list(_npm_tree(lock.get("dependencies")))
    found: list[SbomComponent] = []
    for key, entry in packages.items():
        if not isinstance(key, str) or "node_modules/" not in key or not isinstance(entry, Mapping):
            continue
        alias = entry.get("name")
        name = alias if isinstance(alias, str) else key.rsplit("node_modules/", 1)[1]
        component = _npm_entry(name, entry)
        if component is not None:
            found.append(component)
    return found


def requirements_components(text: str, source: str) -> list[SbomComponent]:
    found: list[SbomComponent] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = _REQUIREMENT_RE.match(line)
        if match is None or len(match.group(1)) > _MAX_TEXT or len(match.group(2)) > _MAX_TEXT:
            continue
        found.append(
            SbomComponent(
                ecosystem="pypi",
                name=_pypi_name(match.group(1)),
                version=match.group(2),
                scope="required",
                sha512=None,
                source=source,
            )
        )
    return found


def uv_components(text: str) -> list[SbomComponent]:
    try:
        lock = tomllib.loads(text)
    except (ValueError, TypeError):
        return []
    packages = lock.get("package")
    found: list[SbomComponent] = []
    for entry in packages if isinstance(packages, list) else ():
        if not isinstance(entry, Mapping):
            continue
        source = entry.get("source")
        if isinstance(source, Mapping) and _LOCAL_UV_SOURCES.intersection(source):
            continue
        name = _text(entry.get("name"))
        version = _text(entry.get("version"))
        if name is None or version is None:
            continue
        git = _text(source.get("git")) if isinstance(source, Mapping) else None
        found.append(
            SbomComponent(
                ecosystem="pypi",
                name=_pypi_name(name),
                version=version,
                scope="required",
                sha512=None,
                source="uv.lock",
                vcs_url=f"git+{git}" if git else None,
            )
        )
    return found


def _split_launch(package: str, *, npm: bool) -> tuple[str, str | None] | None:
    """Name and exact version of a launcher spec; tags and ranges keep no version."""

    match = _LAUNCH_RE.match(package)
    if match is None:
        return None
    name, operator, spec = match.groups()
    exact = _NPM_EXACT_RE if npm else _PYPI_EXACT_RE
    version = spec if spec and (operator == "@" or not npm) and exact.match(spec) else None
    if npm:
        return name, version.removeprefix("v") if version else None
    return _pypi_name(name), version


def launcher_components(servers: Sequence[object]) -> list[SbomComponent]:
    """Packages MCP servers start at launch; an unpinned one has no version."""

    found: list[SbomComponent] = []
    for server in servers:
        package = getattr(server, "package", None)
        command = getattr(server, "command", None)
        if not isinstance(package, str) or not isinstance(command, str):
            continue
        launcher = command.lower().removesuffix(".cmd").removesuffix(".exe")
        if launcher not in _NPM_LAUNCHERS and launcher != "uvx":
            continue
        npm = launcher in _NPM_LAUNCHERS
        split = _split_launch(package, npm=npm)
        if split is None:
            continue
        name, version = split
        found.append(
            SbomComponent(
                ecosystem="npm" if npm else "pypi",
                name=name,
                version=version,
                scope="required",
                sha512=None,
                source="mcp-launcher",
            )
        )
    return found


def _is_dev_requirements(filename: str) -> bool:
    """requirements-dev.txt, requirements_test.txt and the like are not shipped."""

    words = re.split(r"[-_.]", filename.lower().removeprefix("requirements").removesuffix(".txt"))
    return any(word in _DEV_REQUIREMENTS for word in words)


def collect_components(plugin_dir: Path, servers: Sequence[object]) -> list[SbomComponent]:
    found: list[SbomComponent] = []
    if (text := _read(plugin_dir / "package-lock.json")) is not None:
        found.extend(npm_components(text))
    if (text := _read(plugin_dir / "uv.lock")) is not None:
        found.extend(uv_components(text))
    try:
        requirement_files = sorted(plugin_dir.glob("requirements*.txt"))
    except OSError:
        requirement_files = []
    for path in requirement_files:
        if _is_dev_requirements(path.name):
            continue
        if (text := _read(path)) is not None:
            found.extend(requirements_components(text, path.name))
    locked = {(component.ecosystem, component.name) for component in found}
    # A locked entry is more specific than an unpinned launcher reference to the same package.
    found.extend(
        component
        for component in launcher_components(servers)
        if component.version is not None or (component.ecosystem, component.name) not in locked
    )
    unique: dict[str, SbomComponent] = {}
    for component in found:
        unique.setdefault(component.purl, component)
    return sorted(unique.values(), key=lambda component: component.purl)


def _component_json(component: SbomComponent) -> dict[str, object]:
    document: dict[str, object] = {
        "type": "library",
        "bom-ref": component.purl,
        "name": component.name,
        "purl": component.purl,
        "scope": component.scope,
        "properties": [{"name": "hol:source", "value": component.source}],
    }
    if component.version:
        document["version"] = component.version
    if component.sha512:
        document["hashes"] = [{"alg": "SHA-512", "content": component.sha512}]
    return document


def build_plugin_release_sbom(
    *,
    plugin_dir: Path,
    servers: Sequence[object],
    repository: str,
    commit_sha: str,
    plugin_name: str | None,
    plugin_version: str | None,
    guard_version: str,
) -> PluginReleaseSbom | None:
    """The SBOM for one release, or None when it declares no packages or too many to list."""

    components = collect_components(plugin_dir, servers)
    if not components or len(components) > MAX_COMPONENTS:
        return None
    subject: dict[str, object] = {"type": "application", "bom-ref": "plugin", "name": plugin_name or repository}
    if plugin_version:
        subject["version"] = plugin_version
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'https://github.com/{repository}/commit/{commit_sha}')}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "hol-guard", "version": guard_version}]},
            "component": subject,
        },
        "components": [_component_json(component) for component in components],
        "dependencies": [{"ref": "plugin", "dependsOn": [component.purl for component in components]}],
    }
    text = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    return PluginReleaseSbom(
        document=text,
        summary=SbomSummary(
            format="CycloneDX",
            spec_version=SPEC_VERSION,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            components=len(components),
        ),
    )
