"""Pure archive-member and manifest policy for the offline worker."""

from __future__ import annotations

import gzip
import hashlib
import json
import posixpath
import re
import tarfile
import time
from pathlib import Path
from typing import BinaryIO

from .offline_archive_contract import (
    _CONTROL_CHARACTER_RE,
    _NPM_REGISTRY_ALIAS_RE,
    _ArchivePolicyError,
)


def _unsafe_member_reason(member: tarfile.TarInfo) -> str | None:
    raw_name = member.name.replace("\\", "/")
    normalized_name = posixpath.normpath(raw_name)
    if (
        _CONTROL_CHARACTER_RE.search(raw_name)
        or raw_name.startswith("/")
        or normalized_name in {".", ".."}
        or normalized_name.startswith("../")
    ):
        return "unsafe_path"
    first_component = normalized_name.split("/", 1)[0]
    if ":" in first_component:
        return "unsafe_path"
    if member.ischr() or member.isblk() or member.isfifo():
        return "special_file"
    if member.issym() or member.islnk():
        raw_target = (member.linkname or "").replace("\\", "/")
        if not raw_target or raw_target.startswith("/"):
            return "unsafe_link"
        resolved_target = (
            posixpath.normpath(raw_target)
            if member.islnk()
            else posixpath.normpath(posixpath.join(posixpath.dirname(normalized_name), raw_target))
        )
        if resolved_target == ".." or resolved_target.startswith("../"):
            return "unsafe_link"
        if ":" in resolved_target.split("/", 1)[0]:
            return "unsafe_link"
    return None


def _member_kind(member: tarfile.TarInfo) -> str | None:
    if member.isdir():
        return "directory"
    if member.isfile():
        return "file"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return None


def _member_path_conflicts(name: str, kind: str, seen: dict[str, str]) -> bool:
    if name in seen:
        return True
    components = name.split("/")
    for index in range(1, len(components)):
        ancestor = "/".join(components[:index])
        ancestor_kind = seen.get(ancestor)
        if ancestor_kind is not None and ancestor_kind != "directory":
            return True
    if kind != "directory":
        descendant_prefix = f"{name}/"
        if any(existing.startswith(descendant_prefix) for existing in seen):
            return True
    return False


def _normalized_link_target(member: tarfile.TarInfo, normalized_name: str) -> str | None:
    raw_target = (member.linkname or "").replace("\\", "/")
    if not raw_target or _CONTROL_CHARACTER_RE.search(raw_target) or raw_target.startswith("/"):
        return None
    if member.islnk():
        resolved_target = posixpath.normpath(raw_target)
    else:
        resolved_target = posixpath.normpath(posixpath.join(posixpath.dirname(normalized_name), raw_target))
    if resolved_target in {".", ".."} or resolved_target.startswith("../"):
        return None
    if ":" in resolved_target.split("/", 1)[0]:
        return None
    return resolved_target


def _install_script_risk(payload: bytes) -> tuple[str, str] | None:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return (
            "external_archive_manifest_invalid",
            "External archive contains an invalid package manifest.",
        )
    if not isinstance(parsed, dict):
        return (
            "external_archive_manifest_invalid",
            "External archive contains an invalid package manifest.",
        )
    for dependency_group in (
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "devDependencies",
    ):
        dependencies = parsed.get(dependency_group)
        if dependencies is None:
            continue
        if not isinstance(dependencies, dict) or any(
            not isinstance(name, str) or not isinstance(specifier, str) for name, specifier in dependencies.items()
        ):
            return (
                "external_archive_manifest_invalid",
                "External archive contains an invalid dependency declaration.",
            )
        if any(_npm_dependency_specifier_requires_external_fetch(specifier) for specifier in dependencies.values()):
            return (
                "external_archive_nested_source_dependency",
                "External archive declares a non-registry source dependency that cannot be digest-bound.",
            )
    scripts = parsed.get("scripts")
    if scripts is None:
        return None
    if not isinstance(scripts, dict):
        return (
            "external_archive_manifest_invalid",
            "External archive contains an invalid package script declaration.",
        )
    for key in (
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "preprepare",
        "prepare",
        "postprepare",
    ):
        value = scripts.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = value.lower()
        touches_credentials = bool(
            re.search(
                r"\b(?:npm_token|node_auth_token|_authtoken|pypi_token)\b|\.npmrc|\.pypirc",
                normalized,
            )
        )
        exfiltrates = bool(
            re.search(
                r"\b(?:curl|wget|axios|urllib)\b|\bhttps?\.request\b|\bfetch\s*\(|\brequests\.",
                normalized,
            )
        )
        if touches_credentials and exfiltrates:
            return (
                "credential_theft_install_script",
                "External archive install script attempts to read credentials and exfiltrate them.",
            )
        return (
            "tarball_install_script",
            "External archive declares install-time scripts and was blocked.",
        )
    return None


def _npm_dependency_specifier_requires_external_fetch(specifier: str) -> bool:
    normalized = specifier.strip().lower()
    if not normalized:
        return True
    if normalized.startswith(
        (
            "http:",
            "https:",
            "file:",
            "link:",
            "git:",
            "git+",
            "github:",
            "gitlab:",
            "bitbucket:",
            "ssh:",
            "workspace:",
            "portal:",
            "patch:",
            "./",
            "../",
            "/",
            "~",
        )
    ):
        return True
    if normalized.startswith("git@"):
        return True
    if normalized.startswith("npm:"):
        # npm aliases remain registry-only only when both the aliased package
        # and optional selector are plain registry syntax.  Nested protocols
        # such as npm:pkg@exec:... must not inherit this exception.
        return _NPM_REGISTRY_ALIAS_RE.fullmatch(normalized) is None
    # Yarn and other package managers add executable/non-registry protocols
    # (for example exec: and jsr:).  Permit no colon protocol unless it was the
    # validated npm registry alias above.
    if ":" in normalized or "\\" in normalized:
        return True
    if "/" in normalized and not normalized.startswith("npm:"):
        return True
    return re.search(r"@(?:https?|file|link|git\+https?|git\+ssh):", normalized) is not None


def _python_build_script_risk(filename: str, payload: bytes) -> tuple[str, str] | None:
    del payload
    if filename == "setup.py":
        return (
            "python_build_script_risk",
            "External archive contains executable legacy Python build metadata.",
        )
    if filename == "pyproject.toml":
        return (
            "python_build_backend_risk",
            "External archive declares Python build hooks that cannot be safely executed offline.",
        )
    return None


def _hash_stream(source: BinaryIO, *, max_bytes: int, deadline: float) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError
        chunk = source.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            raise ValueError("archive_size_limit")
        digest.update(chunk)
    return digest.hexdigest(), size


def _hash_file(path: Path, *, max_bytes: int, deadline: float) -> tuple[str, int]:
    with path.open("rb") as source:
        return _hash_stream(source, max_bytes=max_bytes, deadline=deadline)


def _preflight_expanded_tar_stream(
    source: BinaryIO,
    *,
    compressed_size: int,
    max_expanded_bytes: int,
    max_decompression_ratio: float,
    deadline: float,
) -> None:
    source.seek(0)
    magic = source.read(6)
    source.seek(0)
    if magic.startswith((b"BZh", b"\xfd7zXZ\x00")):
        raise _ArchivePolicyError(
            "external_archive_unsupported_format",
            "External archive uses an unsupported compression format.",
        )
    reader: BinaryIO | gzip.GzipFile
    gzip_reader: gzip.GzipFile | None = None
    if magic.startswith(b"\x1f\x8b"):
        gzip_reader = gzip.GzipFile(fileobj=source, mode="rb")
        reader = gzip_reader
    else:
        reader = source
    expanded_size = 0
    try:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError
            chunk = reader.read(64 * 1024)
            if not chunk:
                break
            expanded_size += len(chunk)
            if expanded_size > max_expanded_bytes:
                raise _ArchivePolicyError(
                    "external_archive_expanded_size_limit",
                    "External archive exceeded Guard's expanded-stream limit.",
                )
            if expanded_size > max(1, compressed_size) * max_decompression_ratio:
                raise _ArchivePolicyError(
                    "external_archive_decompression_ratio_limit",
                    "External archive exceeded Guard's decompression-ratio limit.",
                )
    finally:
        if gzip_reader is not None:
            gzip_reader.close()
        source.seek(0)
