"""The files Guard reads, but never runs, to learn what a script takes.

A script's own source says what it takes and whether it answers --help
before anything runs it. The reading is the resident's; this module only
finds the files: the verified script itself, and the few local modules it
imports from inside its own folder.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .local_cli_identity import UnlistedCliIdentity

SCRIPT_SOURCE_LIMIT = 32 * 1024
# Enough for an entry point that hands its arguments to a module beside it,
# and few enough that a script importing many files is not read in full.
MAX_FOLLOWED_IMPORTS = 4
_SCRIPT_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py", ".rb", ".sh", ".bash", ".zsh"})


def script_source_path(identity: UnlistedCliIdentity, argv: Sequence[str]) -> tuple[str, bool] | None:
    """The verified script a --help argv would run, and whether it needs a ``#!`` line.

    A script launched through its interpreter has ``argv`` of
    ``(interpreter, script, "--help")``. One run directly has ``(script,
    "--help")`` and counts only when the file starts with a ``#!`` line, so a
    compiled program is never read as text.
    """

    if identity.kind == "script" and len(argv) == 3:
        path, shebang_only = str(argv[1]), False
    elif identity.kind == "executable" and len(argv) == 2:
        path, shebang_only = str(argv[0]), True
    else:
        return None
    return (path, shebang_only) if safe_probe_path(path) else None


def read_script_source(path: str, *, shebang_only: bool) -> str | None:
    """The start of a script's text, or None when it is not a readable script."""

    if not safe_probe_path(path):
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(SCRIPT_SOURCE_LIMIT)
    except OSError:
        return None
    if shebang_only and not raw.startswith(b"#!"):
        return None
    source = raw.decode("utf-8", errors="replace")
    return source if source.strip() else None


def local_import_paths(script: str, imports: Sequence[str]) -> tuple[str, ...]:
    """The imported modules worth reading: regular script files inside the script's folder.

    ``imports`` are the ``./``-relative paths the resident read out of the
    source, so they are text the script chose. Each is resolved through
    symlinks and kept only when it still lands inside the folder that holds the
    script itself, which keeps the read away from the rest of the disk.
    """

    try:
        script_path = Path(script).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return ()
    folder = script_path.parent
    found: list[Path] = []
    for entry in imports:
        if len(found) >= MAX_FOLLOWED_IMPORTS:
            break
        module = _local_module(folder, entry, script_path.suffix)
        if module is not None and module != script_path and module not in found:
            found.append(module)
    return tuple(str(path) for path in found)


def _local_module(folder: Path, entry: str, suffix: str) -> Path | None:
    if not entry.startswith("./") or "\x00" in entry:
        return None
    relative = entry[2:]
    candidates = [folder / relative]
    # `import './cli'` names the file without the suffix it shares with the script.
    if suffix and not Path(relative).suffix:
        candidates.append(folder / f"{relative}{suffix}")
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            continue
        if not resolved.is_relative_to(folder) or resolved.suffix.lower() not in _SCRIPT_SUFFIXES:
            continue
        if safe_probe_path(str(resolved)):
            return resolved
    return None


def safe_probe_path(path_text: str) -> bool:
    path = Path(path_text)
    if not path.is_absolute():
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return False
    if not resolved.is_file():
        return False
    parts = [part.lower() for part in resolved.parts]
    return not (len(parts) > 1 and parts[0] == "/" and parts[1] in {"proc", "dev", "sys"})
