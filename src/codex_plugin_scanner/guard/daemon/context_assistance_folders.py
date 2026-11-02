"""Bounded folder listing for the dashboard's project picker.

Only names, kinds and sizes leave this module; no file is opened. The grant
stays native and re-validates every path, so a listing never grants access.
"""

from __future__ import annotations

import contextlib
import os
import stat
import string
import sys
from pathlib import Path, PurePosixPath

SCHEMA = "guard-context-folders.v1"
MAX_ENTRIES = 400
MAX_FILE_BYTES = 65_536
MAX_SUGGESTED = 8
_MAX_PATH = 4096
_PROJECT_MARKERS = (
    ".git",
    ".hg",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "deno.json",
    "Package.swift",
    "mix.exs",
)
_PLACES = (
    "Desktop",
    "Documents",
    "Developer",
    "Projects",
    "projects",
    "code",
    "Code",
    "dev",
    "src",
    "repos",
    "git",
    "GitHub",
    "Documents/GitHub",
    "workspace",
)
_NOISE_DIRS = frozenset({"node_modules", "__pycache__"})
_SECRET_WORDS = ("secret", "credential", "password", "passwd", "token", "private_key", "privatekey")
_SECRET_EXTENSIONS = frozenset({"pem", "key", "p12", "pfx", "jks", "keystore", "kdbx", "ppk", "gpg", "asc", "der"})
_SECRET_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "netrc", "_netrc", "htpasswd"})
_SECRET_DIR_WORDS = frozenset(
    {
        "ssh",
        "aws",
        "gnupg",
        "gpg",
        "auth",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "token",
        "tokens",
        "keys",
        "keychain",
        "keychains",
        "vault",
    }
)
_SOURCE_EXTENSIONS = frozenset(
    {
        "py",
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "jsx",
        "rs",
        "go",
        "java",
        "kt",
        "swift",
        "rb",
        "php",
        "c",
        "h",
        "cc",
        "cpp",
        "hpp",
        "cs",
        "scala",
        "sh",
        "sql",
        "vue",
        "svelte",
        "lua",
        "dart",
        "ex",
        "exs",
        "md",
        "mdx",
    }
)
_BINARY_EXTENSIONS = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "ico",
        "icns",
        "bmp",
        "tiff",
        "svgz",
        "pdf",
        "zip",
        "gz",
        "tgz",
        "bz2",
        "xz",
        "7z",
        "rar",
        "tar",
        "jar",
        "war",
        "exe",
        "dll",
        "so",
        "dylib",
        "a",
        "o",
        "obj",
        "class",
        "wasm",
        "bin",
        "dat",
        "db",
        "sqlite",
        "sqlite3",
        "mp3",
        "mp4",
        "mov",
        "avi",
        "wav",
        "flac",
        "ogg",
        "woff",
        "woff2",
        "ttf",
        "otf",
        "eot",
        "psd",
        "sketch",
        "fig",
        "dmg",
        "pkg",
        "msi",
        "iso",
        "lock",
    }
)
_SUGGESTED_NAMES = (
    "README.md",
    "README",
    "README.txt",
    "README.rst",
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "DESIGN.md",
    "docs/README.md",
    "docs/index.md",
)


class FolderError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _secret_file(name: str) -> bool:
    lower = name.lower()
    suffix = lower.rsplit(".", 1)[-1] if "." in lower else ""
    return (
        lower.startswith(".env")
        or lower.lstrip(".") in _SECRET_NAMES
        or suffix in _SECRET_EXTENSIONS
        or (suffix not in _SOURCE_EXTENSIONS and any(word in lower for word in _SECRET_WORDS))
    )


def _secret_dir(name: str) -> bool:
    # Native grants refuse credential stores; hide them so a pick cannot fail.
    words = name.lower().lstrip(".").replace("-", "_").replace(".", "_").split("_")
    return words[0] in _SECRET_DIR_WORDS if len(words) == 1 else words[-1] in _SECRET_DIR_WORDS - {"auth", "vault"}


def _hidden(entry: os.DirEntry[str]) -> bool:
    if entry.name.startswith("."):
        return True
    if sys.platform == "win32":
        try:
            attributes = entry.stat(follow_symlinks=False).st_file_attributes  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            return False
        return bool(attributes & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM))  # type: ignore[attr-defined]
    return False


def _resolve_directory(raw: object) -> Path:
    if raw is None or raw == "":
        raw = str(Path.home())
    if not isinstance(raw, str) or len(raw) > _MAX_PATH or "\x00" in raw:
        raise FolderError("folder_input_invalid", 400)
    candidate = Path(os.path.expanduser(raw.strip()))
    if not candidate.is_absolute():
        raise FolderError("folder_not_absolute", 400)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise FolderError("folder_not_found", 404) from None
    if not resolved.is_dir():
        raise FolderError("folder_not_directory", 400)
    return resolved


def _scan(directory: Path) -> list[os.DirEntry[str]]:
    try:
        with os.scandir(directory) as iterator:
            return sorted(iterator, key=lambda entry: (entry.name.lower(), entry.name))
    except PermissionError:
        raise FolderError("folder_denied", 403) from None
    except OSError:
        raise FolderError("folder_unreadable", 403) from None


def _is_project(path: str) -> bool:
    return any(os.path.lexists(os.path.join(path, marker)) for marker in _PROJECT_MARKERS)


def _places(home: Path) -> list[dict[str, str]]:
    seen: set[str] = set()
    places = [{"label": "Home", "path": str(home), "kind": "home"}]
    seen.add(os.path.normcase(str(home)))
    for name in _PLACES:
        candidate = home / name
        try:
            if candidate.is_symlink() or not candidate.is_dir():
                continue
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        key = os.path.normcase(str(resolved))
        if key in seen:
            continue
        seen.add(key)
        places.append({"label": name.split("/")[-1], "path": str(resolved), "kind": "folder"})
    return places


def _roots() -> list[dict[str, str]]:
    if sys.platform != "win32":
        return [{"label": "This computer", "path": "/"}]
    return [
        {"label": f"{letter}: drive", "path": f"{letter}:\\"}
        for letter in string.ascii_uppercase
        if os.path.isdir(f"{letter}:\\")
    ]


def list_folders(payload: dict[str, object]) -> dict[str, object]:
    directory = _resolve_directory(payload.get("path"))
    show_hidden = payload.get("hidden") is True
    home = Path.home()
    entries: list[dict[str, object]] = []
    truncated = False
    for entry in _scan(directory):
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        if (not show_hidden and _hidden(entry)) or _secret_dir(entry.name):
            continue
        if len(entries) == MAX_ENTRIES:
            truncated = True
            break
        entries.append({"name": entry.name, "path": entry.path, "project": _is_project(entry.path)})
    parent = directory.parent if directory.parent != directory else None
    return {
        "schema": SCHEMA,
        "mode": "folders",
        "path": str(directory),
        "name": directory.name or str(directory),
        "parent": str(parent) if parent else None,
        "project": _is_project(str(directory)),
        "home": str(home),
        "separator": os.sep,
        "places": _places(home),
        "roots": _roots(),
        "entries": entries,
        "truncated": truncated,
    }


def _relative(raw: object) -> PurePosixPath:
    if raw is None or raw == "":
        return PurePosixPath()
    if not isinstance(raw, str) or len(raw) > 1024 or "\\" in raw or ":" in raw or "\x00" in raw:
        raise FolderError("folder_input_invalid", 400)
    relative = PurePosixPath(raw.strip("/"))
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise FolderError("folder_input_invalid", 400)
    return relative


def _file_row(entry: os.DirEntry[str], relative: PurePosixPath) -> dict[str, object] | None:
    try:
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            return None
        size = entry.stat(follow_symlinks=False).st_size
    except OSError:
        return None
    suffix = entry.name.lower().rsplit(".", 1)[-1] if "." in entry.name else ""
    reason = None
    if suffix in _BINARY_EXTENSIONS:
        reason = "not_text"
    elif size == 0:
        reason = "empty"
    elif size > MAX_FILE_BYTES:
        reason = "too_large"
    return {
        "name": entry.name,
        "relative": str(relative / entry.name),
        "size": size,
        "available": reason is None,
        "reason": reason,
    }


def _suggested(workspace: Path) -> list[dict[str, object]]:
    picks: list[dict[str, object]] = []
    seen: set[str] = set()
    names = list(_SUGGESTED_NAMES)
    docs = workspace / "docs"
    if docs.is_dir() and not docs.is_symlink():
        with contextlib.suppress(FolderError):
            names += sorted(f"docs/{entry.name}" for entry in _scan(docs) if entry.name.lower().endswith(".md"))
    for relative in names:
        path = workspace / relative
        key = relative.lower()
        if key in seen or len(picks) == MAX_SUGGESTED:
            continue
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_FILE_BYTES:
            seen.add(key)
            picks.append({"relative": relative, "size": info.st_size})
    return picks


def list_files(payload: dict[str, object]) -> dict[str, object]:
    if not payload.get("workspace"):
        raise FolderError("folder_input_invalid", 400)
    workspace = _resolve_directory(payload.get("workspace"))
    relative = _relative(payload.get("path"))
    directory = workspace.joinpath(*relative.parts)
    if directory.is_symlink() or not directory.is_dir():
        raise FolderError("folder_not_found", 404)
    folders: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    truncated = False
    for entry in _scan(directory):
        if _hidden(entry) or entry.name in _NOISE_DIRS:
            continue
        if len(folders) + len(files) == MAX_ENTRIES:
            truncated = True
            break
        try:
            is_folder = not entry.is_symlink() and entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if is_folder:
            if _secret_dir(entry.name):
                continue
            folders.append({"name": entry.name, "relative": str(relative / entry.name)})
            continue
        if _secret_file(entry.name):
            continue
        row = _file_row(entry, relative)
        if row is not None:
            files.append(row)
    return {
        "schema": SCHEMA,
        "mode": "files",
        "workspace": str(workspace),
        "path": "" if not relative.parts else str(relative),
        "entries": folders,
        "files": files,
        "suggested": _suggested(workspace) if not relative.parts else [],
        "max_file_bytes": MAX_FILE_BYTES,
        "truncated": truncated,
    }


def browse(payload: dict[str, object]) -> dict[str, object]:
    mode = payload.get("mode", "folders")
    if mode == "folders":
        return list_folders(payload)
    if mode == "files":
        return list_files(payload)
    raise FolderError("folder_input_invalid", 400)
