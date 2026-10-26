"""Running the output filters native authority classified after a contained core.

`contained_output_filters.rs` decides which chain of `| head -N`, `| tail -N`,
`| grep` and `| rg` stages a contained command may carry: at most three, each
reading only standard input, with no file operand, pattern file, recursion or
other output, so a stage can only print lines of the text it is given. That
grammar lives there alone. This module carries out the chain it chose.

Head and tail run in-process. A matcher runs as its own binary on the text the
core already produced, in this process rather than in the core's sandbox. The
environment is built here, never the caller's. The binary is the installed
one, located by ownership rather than by the caller's `PATH`; a matcher an
agent could rewrite is one every plain `grep` or `rg` search already runs, so
locating it this way is what this screen can decide, and the sandbox the core
ran in does not extend here.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

_GREP_PROGRAMS = {"grep": (), "egrep": ("-E",), "fgrep": ("-F",)}
_GREP_BINARIES = (Path("/usr/bin/grep"), Path("/bin/grep"))
# ripgrep ships from a package manager rather than the system image, so it is
# looked for in the ordinary install directories instead of a fixed path.
_RG_DIRECTORIES = (
    Path("/usr/bin"),
    Path("/bin"),
    Path("/usr/local/bin"),
    Path("/opt/homebrew/bin"),
    Path("/opt/local/bin"),
    Path("/home/linuxbrew/.linuxbrew/bin"),
)
_LOCALE = ("LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE")
_FILTER_TIMEOUT_SECONDS = 60

Stage = tuple[str, ...]


def keep_lines(lines: list[str], kind: str, count: int) -> list[str]:
    if kind == "head":
        return lines[:count]
    return lines[len(lines) - count :] if count else []


def _owners() -> set[int]:
    """The identities a filter binary may belong to: root or this user."""
    return {0, os.getuid()} if hasattr(os, "getuid") else {0}


def _rewritable_only_by_owner(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and info.st_uid in _owners() and not info.st_mode & 0o022


def _trusted_ripgrep() -> str:
    """The installed ripgrep: an executable file only its owner can rewrite.

    Its path is not fixed the way the system grep's is, so the install
    directories are searched in turn and the resolved file must belong to root
    or to this user with no group or other write bit. A name that cannot be
    executed is not the install, so the search goes on to the next directory
    rather than failing on it.
    """
    for directory in _RG_DIRECTORIES:
        try:
            resolved = (directory / "rg").resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if _rewritable_only_by_owner(info) and os.access(resolved, os.X_OK):
            return str(resolved)
    raise RuntimeError("no trusted ripgrep")


def _trusted_grep() -> str:
    """The system grep: a root-owned regular file nobody else can rewrite."""
    for candidate in _GREP_BINARIES:
        try:
            info = candidate.stat()
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022:
            return str(candidate)
    raise RuntimeError("no trusted system grep")


def _matcher_command(program: str, arguments: list[str]) -> list[str]:
    """The screened binary and argument list one matcher stage runs.

    Native authority already refused every argument that would read something
    other than standard input, so only the program name is settled here: this
    module spawns the matchers it knows how to locate by ownership, and
    nothing else.
    """
    if program == "rg":
        return [_trusted_ripgrep(), *arguments]
    if program in _GREP_PROGRAMS:
        return [_trusted_grep(), *_GREP_PROGRAMS[program], *arguments]
    raise ValueError("unsupported output filter")


def _match_lines(text: str, stage: Stage) -> tuple[str, str, int]:
    program, *arguments = stage
    try:
        command = _matcher_command(program, arguments)
    except RuntimeError:
        # The shape was accepted before the core ran, so the core has already
        # done its work. A machine without the matcher installed gets the
        # status a shell gives a missing program, not an exception from the
        # wrapper.
        return "", f"hol-guard: {program}: not found\n", 127
    # No `RIPGREP_CONFIG_PATH` or `GREP_OPTIONS`: the environment is built here.
    environment = {"PATH": "/usr/bin:/bin"}
    environment.update({name: os.environ[name] for name in _LOCALE if name in os.environ})
    completed = subprocess.run(  # screened binary, native-validated stdin-only arguments
        command,
        input=text.encode("utf-8", "surrogateescape"),
        capture_output=True,
        env=environment,
        timeout=_FILTER_TIMEOUT_SECONDS,
        check=False,
    )
    return (
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
        completed.returncode,
    )


def apply_filters(text: str, stages: tuple[Stage, ...]) -> tuple[str, str, int]:
    """Run the chain over `text`: (output, matcher diagnostics, last stage's status)."""
    errors: list[str] = []
    status = 0
    for stage in stages:
        if stage[0] in {"head", "tail"}:
            text = "".join(keep_lines(text.splitlines(keepends=True), stage[0], int(stage[1])))
            status = 0
            continue
        text, error, status = _match_lines(text, stage)
        errors.append(error)
    return text, "".join(errors), status
