"""The output directory a project's Vite config names, when it is a literal path.

Projects often build into a directory other than `dist`, such as a static
folder another package serves. The build-output profile may write there only
when the config spells the directory as a literal (optionally through
`resolve(__dirname, ...)` or `join(__dirname, ...)`), it stays inside the
workspace, and it does not cover the package's own sources.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .restricted_pytest_model import RestrictedPytestError
from .restricted_pytest_validation import _path_is_within

_CONFIG_NAMES = tuple(f"vite.config.{suffix}" for suffix in ("ts", "mts", "cts", "js", "mjs", "cjs"))
_MAX_CONFIG_BYTES = 256 * 1024
_WEB_ASSETS = frozenset(
    {
        ".avif",
        ".br",
        ".css",
        ".eot",
        ".gif",
        ".gz",
        ".htm",
        ".html",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".map",
        ".mjs",
        ".mp3",
        ".mp4",
        ".otf",
        ".png",
        ".svg",
        ".ttf",
        ".txt",
        ".wasm",
        ".wav",
        ".webm",
        ".webmanifest",
        ".webp",
        ".woff",
        ".woff2",
        ".xml",
    }
)
_MAX_EXISTING_FILES = 20_000
_OUT_DIR = re.compile(r"\boutDir\b")
_LITERAL = re.compile(
    r"""\boutDir\s*:\s*(?:
        (?:path\.)?(?:resolve|join)\(\s*__dirname\s*,\s*(?P<q1>['"])(?P<joined>[^'"\\$`]+)(?P=q1)\s*\)
        |(?P<q2>['"])(?P<plain>[^'"\\$`]+)(?P=q2)
    )""",
    re.VERBOSE,
)


def declared_vite_output(cwd: Path, workspace: Path) -> Path | None:
    """The config's literal output directory, None when the config names none.

    Raises when the config names an output directory that cannot be verified,
    so the build reports why instead of failing on a denied write.
    """
    configs = [cwd / name for name in _CONFIG_NAMES if (cwd / name).is_file()]
    if len(configs) != 1 or configs[0].is_symlink():
        return None
    try:
        raw = configs[0].read_bytes()[: _MAX_CONFIG_BYTES + 1]
    except OSError:
        return None
    text = raw.decode("utf-8", errors="replace")
    if not _OUT_DIR.search(text):
        return None
    matches = list(_LITERAL.finditer(text))
    if len(raw) > _MAX_CONFIG_BYTES or len(matches) != 1 or len(_OUT_DIR.findall(text)) != 1:
        raise _unverified()
    spelled = matches[0].group("joined") or matches[0].group("plain")
    output = Path(_normalized(cwd / spelled))
    if not _admissible(output, cwd=cwd, workspace=workspace):
        raise _unverified()
    return output


def _normalized(path: Path) -> str:
    parts: list[str] = []
    for part in path.parts:
        if part == "..":
            if len(parts) > 1:
                parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    return str(Path(*parts))


def _admissible(output: Path, *, cwd: Path, workspace: Path) -> bool:
    if output == workspace or not _path_is_within(output, workspace) or _path_is_within(cwd, output):
        return False
    parts = output.relative_to(workspace).parts
    if any(part.startswith(".") or part == "node_modules" for part in parts):
        return False
    # Every existing component is a real directory, so the grant cannot be
    # redirected through a link.
    for index in range(len(parts)):
        component = workspace.joinpath(*parts[: index + 1])
        if component.is_symlink() or (component.exists() and not component.is_dir()):
            return False
        if (component / "package.json").exists():
            return False
    return _holds_only_built_assets(output)


def _holds_only_built_assets(output: Path) -> bool:
    """An existing directory the build may empty holds nothing but web assets.

    Vite empties its output first, so a directory holding sources or scripts
    is never accepted as a build target.
    """
    if not output.exists():
        return True
    visited = 0
    for _directory, _folders, files in os.walk(output, followlinks=False):
        if "package.json" in files:
            return False
        for name in files:
            visited += 1
            if visited > _MAX_EXISTING_FILES:
                return False
            if name not in {".gitkeep", ".DS_Store"} and Path(name).suffix.lower() not in _WEB_ASSETS:
                return False
    return True


def config_bundle_directory(cwd: Path, workspace: Path, modules: Path) -> Path | None:
    """Where Vite's default loader writes the bundled config, when Guard can grant it.

    Vite bundles `vite.config.ts` into `node_modules/.vite-temp` next to the
    config, imports that one file and deletes it. Granting that directory lets
    configs that use `__dirname` load as they do outside Guard. None keeps the
    write-free runner loader.
    """
    nearest = next(
        (directory / "node_modules" for directory in (cwd, *cwd.parents) if (directory / "node_modules").exists()),
        None,
    )
    if nearest is None or nearest != modules or not _path_is_within(nearest, workspace):
        return None
    current = nearest
    while current != workspace:
        if current.is_symlink():
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent
    temp = nearest / ".vite-temp"
    if nearest.is_symlink() or not nearest.is_dir() or temp.is_symlink():
        return None
    if temp.exists():
        if not temp.is_dir():
            return None
        entries = list(os.scandir(temp))
        if len(entries) > 256 or any(not entry.is_file(follow_symlinks=False) for entry in entries):
            return None
    return temp


def _unverified() -> RestrictedPytestError:
    return RestrictedPytestError(
        "node_build_invalid_output",
        "The Vite config sets an output directory HOL Guard could not verify inside the project.",
    )


__all__ = ["config_bundle_directory", "declared_vite_output"]
