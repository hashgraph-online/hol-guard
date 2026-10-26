#!/usr/bin/env python3
"""Pack the HOL Guard MCP bundle into a zip archive.

The archive is the ``.mcpb`` file attached to a release. This script checks the
manifest fields the bundle ships and writes the archive with the standard
library. It does not install or invoke the MCPB CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
import urllib.parse
import zipfile
from pathlib import Path

import tomllib

MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_STRING = 8 * 1024
MAX_LIST = 64
MAX_FILES = 8
SKIP_DIR_NAMES = {"__pycache__", ".git"}
SKIP_FILE_NAMES = {".DS_Store"}
SKIP_SUFFIXES = {".pyc"}
TOP_LEVEL_KEYS = {
    "$schema",
    "dxt_version",
    "manifest_version",
    "name",
    "display_name",
    "version",
    "description",
    "long_description",
    "author",
    "repository",
    "homepage",
    "documentation",
    "support",
    "icon",
    "server",
    "tools",
    "tools_generated",
    "keywords",
    "license",
    "compatibility",
}
SERVER_TYPES = {"python", "node", "binary", "uv"}
PLATFORMS = {"darwin", "win32", "linux"}
ZIP_DATE = (2020, 1, 1, 0, 0, 0)


class PackError(ValueError):
    """The bundle cannot be packed."""


def pack_bundle(root: Path, output: Path) -> list[str]:
    """Validate ``root`` and write the archive to ``output``. Return member names."""
    bundle = _directory(root)
    _output_outside(bundle, output)
    files = _bundle_files(bundle)
    version, expected = _manifest(bundle, files)
    _pyproject(bundle, files, version)
    actual = {name for name, _path in files}
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    if extra or missing:
        raise PackError(f"bundle files must be {sorted(expected)}; extra={extra} missing={missing}")
    _write_archive(files, output)
    return [name for name, _path in files]


def _directory(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise PackError(f"bundle directory is missing: {root}")
    return root


def _output_outside(bundle: Path, output: Path) -> None:
    if output.exists() and (output.is_symlink() or output.is_dir()):
        raise PackError("output must be a regular file path")
    bundle_root = bundle.resolve()
    destination = output.parent.resolve() / output.name
    if destination == bundle_root or bundle_root in destination.parents:
        raise PackError("output must be outside the bundle directory")


def _bundle_files(root: Path) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        if current_path.is_symlink():
            raise PackError(f"refuse symlink: {current_path.relative_to(root).as_posix()}")
        kept: list[str] = []
        for name in dirnames:
            path = current_path / name
            if path.is_symlink():
                raise PackError(f"refuse symlink: {path.relative_to(root).as_posix()}")
            if name not in SKIP_DIR_NAMES:
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise PackError(f"refuse symlink: {relative}")
            if name in SKIP_FILE_NAMES or path.suffix in SKIP_SUFFIXES:
                continue
            if not path.is_file():
                raise PackError(f"refuse non-file: {relative}")
            found.append((relative, path))
            if len(found) > MAX_FILES:
                raise PackError(f"bundle has more than {MAX_FILES} files")
    found.sort(key=lambda item: item[0])
    return found


def _manifest(root: Path, files: list[tuple[str, Path]]) -> tuple[str, set[str]]:
    path = root / "manifest.json"
    if not any(name == "manifest.json" for name, _file in files):
        raise PackError("manifest.json is missing")
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise PackError("manifest.json exceeds 64 KiB")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PackError("manifest.json is not UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise PackError("manifest.json must be an object")
    unknown = sorted(set(payload) - TOP_LEVEL_KEYS)
    if unknown:
        raise PackError(f"unsupported manifest field: {', '.join(unknown)}")
    if payload.get("manifest_version") != "0.4":
        raise PackError("manifest_version must be 0.4")
    if "dxt_version" in payload and payload["dxt_version"] != "0.4":
        raise PackError("dxt_version must be 0.4")
    _text(payload, "name")
    version = _text(payload, "version")
    _text(payload, "description")
    for key in ("display_name", "long_description", "license", "$schema"):
        if key in payload:
            _text(payload, key)
    _author(payload.get("author"))
    if "repository" in payload:
        _repository(payload["repository"])
    for key in ("homepage", "documentation", "support"):
        if key in payload:
            _https(payload[key], key)
    required = {"manifest.json", "pyproject.toml"}
    if "icon" in payload:
        icon = _icon(payload["icon"])
        if icon is not None:
            required.add(icon)
    required.add(_server(payload.get("server")))
    if "tools" in payload:
        _tools(payload["tools"])
    if "tools_generated" in payload and not isinstance(payload["tools_generated"], bool):
        raise PackError("tools_generated must be a boolean")
    if "keywords" in payload:
        _strings(payload["keywords"], "keywords")
    if "compatibility" in payload:
        _compatibility(payload["compatibility"])
    return version, required


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise PackError(f"duplicate manifest key: {key}")
        payload[key] = value
    return payload


def _text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > MAX_STRING or "\x00" in value:
        raise PackError(f"{key} must be a short string")
    return value


def _https(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > MAX_STRING:
        raise PackError(f"{label} must be an https URL")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or "@" in parsed.netloc:
        raise PackError(f"{label} must be an https URL")


def _icon(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_STRING or "\x00" in value:
        raise PackError("icon must be an https URL or a bundle-relative path")
    if value.startswith("https://"):
        _https(value, "icon")
        return None
    return _relative_file(value)


def _author(value: object) -> None:
    if not isinstance(value, dict):
        raise PackError("author must be an object")
    unknown = sorted(set(value) - {"name", "email", "url"})
    if unknown:
        raise PackError(f"unsupported author field: {', '.join(unknown)}")
    _text(value, "name")
    if "email" in value:
        email = _text(value, "email")
        if email.count("@") != 1 or any(character.isspace() for character in email):
            raise PackError("author.email must be an email address")
    if "url" in value:
        _https(value["url"], "author.url")


def _repository(value: object) -> None:
    if not isinstance(value, dict):
        raise PackError("repository must be an object")
    unknown = sorted(set(value) - {"type", "url"})
    if unknown:
        raise PackError(f"unsupported repository field: {', '.join(unknown)}")
    _text(value, "type")
    _https(value.get("url"), "repository.url")


def _server(value: object) -> str:
    if not isinstance(value, dict):
        raise PackError("server must be an object")
    unknown = sorted(set(value) - {"type", "entry_point", "mcp_config"})
    if unknown:
        raise PackError(f"unsupported server field: {', '.join(unknown)}")
    if value.get("type") not in SERVER_TYPES:
        raise PackError("server.type is unsupported")
    entry = _relative_file(_text(value, "entry_point"))
    config = value.get("mcp_config")
    if not isinstance(config, dict):
        raise PackError("server.mcp_config must be an object")
    unknown = sorted(set(config) - {"command", "args"})
    if unknown:
        raise PackError(f"unsupported mcp_config field: {', '.join(unknown)}")
    command = _text(config, "command")
    if not command.isascii() or any(character.isspace() for character in command):
        raise PackError("server.mcp_config.command must be a single token")
    if "args" in config:
        _strings(config["args"], "server.mcp_config.args")
    return entry


def _tools(value: object) -> None:
    items = _list(value, "tools")
    for item in items:
        if not isinstance(item, dict):
            raise PackError("tools entries must be objects")
        unknown = sorted(set(item) - {"name", "description"})
        if unknown:
            raise PackError(f"unsupported tool field: {', '.join(unknown)}")
        _text(item, "name")
        if "description" in item:
            _text(item, "description")


def _compatibility(value: object) -> None:
    if not isinstance(value, dict):
        raise PackError("compatibility must be an object")
    unknown = sorted(set(value) - {"claude_desktop", "platforms", "runtimes"})
    if unknown:
        raise PackError(f"unsupported compatibility field: {', '.join(unknown)}")
    if "claude_desktop" in value:
        _text(value, "claude_desktop")
    if "platforms" in value:
        platforms = _strings(value["platforms"], "compatibility.platforms")
        if any(platform not in PLATFORMS for platform in platforms):
            raise PackError("compatibility.platforms contains an unsupported platform")
    if "runtimes" in value:
        runtimes = value["runtimes"]
        if not isinstance(runtimes, dict):
            raise PackError("compatibility.runtimes must be an object")
        unknown = sorted(set(runtimes) - {"python", "node"})
        if unknown:
            raise PackError(f"unsupported runtime field: {', '.join(unknown)}")
        for key in ("python", "node"):
            if key in runtimes:
                _text(runtimes, key)


def _strings(value: object, label: str) -> list[str]:
    items = _list(value, label)
    texts: list[str] = []
    for item in items:
        if not isinstance(item, str) or not item or len(item) > MAX_STRING or "\x00" in item:
            raise PackError(f"{label} entries must be short strings")
        texts.append(item)
    return texts


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list) or len(value) > MAX_LIST:
        raise PackError(f"{label} must be a list of at most {MAX_LIST} items")
    return value


def _relative_file(value: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or "\\" in value or ".." in path.parts or "" in path.parts:
        raise PackError(f"path must stay inside the bundle: {value}")
    return path.as_posix()


def _pyproject(root: Path, files: list[tuple[str, Path]], version: str) -> None:
    if not any(name == "pyproject.toml" for name, _file in files):
        raise PackError("pyproject.toml is missing")
    raw = (root / "pyproject.toml").read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise PackError("pyproject.toml exceeds 256 KiB")
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise PackError("pyproject.toml is not valid TOML") from exc
    project = document.get("project")
    if not isinstance(project, dict) or project.get("version") != version:
        raise PackError("pyproject.toml version must match the manifest")
    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list) or f"hol-guard=={version}" not in dependencies:
        raise PackError("pyproject.toml must depend on the manifest version of hol-guard")


def _write_archive(files: list[tuple[str, Path]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, partial_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".partial", dir=output.parent)
    partial = Path(partial_name)
    try:
        with (
            os.fdopen(descriptor, "wb") as handle,
            zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive,
        ):
            for name, path in files:
                data = path.read_bytes()
                if len(data) > MAX_FILE_BYTES:
                    raise PackError(f"{name} exceeds 256 KiB")
                info = zipfile.ZipInfo(filename=name, date_time=ZIP_DATE)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
                info.flag_bits |= 0x800
                archive.writestr(info, data)
        os.replace(partial, output)
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pack a HOL Guard MCP bundle.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        members = pack_bundle(args.bundle, args.output)
    except PackError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"files: {len(members)}")
    for name in members:
        print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
