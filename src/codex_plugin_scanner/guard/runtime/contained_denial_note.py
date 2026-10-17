"""The note a failed workspace-contained run gets when its output names a denial.

The note names what the sandbox blocked: a write outside the workspace,
starting a program outside the allowed roots, a network connection, or a
read outside the workspace. The first output line that names one of those
picks it; a denial with no clearer cause gets the generic note. Markers
match whole words, so a path such as `/usr/libexec` or `rewrite.log` names
no cause, and only errors a sandbox denial produces name one alone. Rust keeps
the same notes and markers in `contained_workspace_sink_denial.rs`, byte for
byte, in the same order.
"""

from __future__ import annotations

from collections.abc import Iterable

_PREFIX = "This command ran inside HOL Guard's workspace sandbox, which "
WRITE_NOTE = (
    _PREFIX + "blocked a write outside the workspace. Only the workspace and $TMPDIR are writable, "
    "apart from protected paths such as Git configuration. Keep files the command writes "
    "inside the workspace or $TMPDIR."
)
EXEC_NOTE = _PREFIX + "blocked starting a program outside the locations it allows."
CONNECT_NOTE = _PREFIX + "blocked a network connection. The sandbox has no network access."
READ_NOTE = _PREFIX + "blocked a read outside the workspace, such as the home directory."
GENERIC_NOTE = (
    _PREFIX + "denied an operation. Only the workspace and $TMPDIR are writable, and there is no "
    "network or home access."
)
# Words that make a line a denial at all.
DENIAL_WORDS = (b"eperm", b"eacces", b"operation not permitted", b"permission denied")
# Per cause, in order: markers that name the cause alone, then words that name
# it on a line that also holds a denial word.
CAUSES = (
    (EXEC_NOTE, (b"spawn eperm", b"spawn eacces"), (b"exec", b"execve", b"posix_spawn")),
    (
        CONNECT_NOTE,
        (
            b"connect eperm",
            b"connect eacces",
            b"network is unreachable",
            b"enetunreach",
            b"getaddrinfo enotfound",
            b"could not resolve host",
            b"nodename nor servname",
        ),
        (b"connect", b"socket"),
    ),
    (
        WRITE_NOTE,
        (b"erofs", b"read-only file system"),
        (b"mkdir", b"rename", b"unlink", b"rmdir", b"symlink", b"copyfile", b"write", b"utime", b"chmod"),
    ),
    (READ_NOTE, (), (b"scandir", b"opendir", b"readdir", b"lstat", b"stat '", b"readlink")),
)


def _word_byte(byte: int) -> bool:
    return byte < 0x80 and (chr(byte).isalnum() or chr(byte) in "/._-")


def _holds(line: bytes, marker: bytes) -> bool:
    """Whether `marker` appears in `line` with no word or path characters joined to either end."""
    start = line.find(marker)
    while start >= 0:
        end = start + len(marker)
        clear_start = start == 0 or not (_word_byte(marker[0]) and _word_byte(line[start - 1]))
        clear_end = end == len(line) or not (_word_byte(marker[-1]) and _word_byte(line[end]))
        if clear_start and clear_end:
            return True
        start = line.find(marker, start + 1)
    return False


def _line_note(line: bytes) -> str | None:
    denial = any(_holds(line, word) for word in DENIAL_WORDS)
    for note, alone, with_denial in CAUSES:
        if any(_holds(line, marker) for marker in alone) or (
            denial and any(_holds(line, word) for word in with_denial)
        ):
            return note
    return None


def denial_note(outputs: Iterable[bytes]) -> str | None:
    """The note for `outputs`, read in order, or None when none names a denial."""
    denied = False
    for output in outputs:
        for line in output.lower().split(b"\n"):
            note = _line_note(line)
            if note is not None:
                return note
            denied = denied or any(_holds(line, word) for word in DENIAL_WORDS)
    return GENERIC_NOTE if denied else None
