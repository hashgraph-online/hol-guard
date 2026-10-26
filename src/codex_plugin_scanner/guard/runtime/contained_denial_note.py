"""The note a failed workspace-contained run gets when its output names a denial.

The note names what the sandbox blocked: a write outside the workspace,
starting a program outside the allowed roots, a network connection, a read
outside the workspace, a pseudo-terminal, or the Docker socket. The first
output line that names one of those picks it; a denial with no clearer cause
gets the generic note. Every note ends with the scope sentence, so an agent
can plan: programs the command starts, including children of an interpreter,
ran contained, and only commands Guard proves safe run directly. Markers
match whole words, so a path such as `/usr/libexec` or `rewrite.log` names
no cause, and only errors a sandbox denial produces name one alone. Rust keeps
the same notes and markers in `contained_workspace_sink_denial.rs`, byte for
byte, in the same order.
"""

from __future__ import annotations

from collections.abc import Iterable

_PREFIX = "This command ran inside HOL Guard's workspace sandbox, which "
SCOPE = (
    " This applies to every program the command starts, including children of an interpreter; "
    "only commands Guard proves safe run directly, outside the sandbox."
)
WRITE_NOTE = (
    _PREFIX + "blocked a write outside the workspace. Only the workspace, $TMPDIR and a private "
    "scratch $HOME are writable, apart from protected paths such as Git configuration. Keep "
    "files the command writes inside the workspace or $TMPDIR." + SCOPE
)
EXEC_NOTE = _PREFIX + "blocked starting a program outside the locations it allows." + SCOPE
CONNECT_NOTE = _PREFIX + "blocked a network connection. The sandbox has no network access." + SCOPE
READ_NOTE = _PREFIX + "blocked a read outside the workspace, such as the home directory." + SCOPE
PTY_NOTE = (
    _PREFIX + "blocked opening a pseudo-terminal. The sandbox has no PTY, so a program that needs "
    "an interactive terminal cannot run contained; use its non-interactive form." + SCOPE
)
DOCKER_NOTE = (
    _PREFIX + "blocked access to the Docker socket. The sandbox never allows Docker, so a command "
    "that needs a container runtime cannot run contained." + SCOPE
)
GENERIC_NOTE = (
    _PREFIX + "denied an operation. Only the workspace, $TMPDIR and a private scratch $HOME are "
    "writable, and there is no network, real home directory, PTY or Docker socket access." + SCOPE
)
# Words that make a line a denial at all.
DENIAL_WORDS = (b"eperm", b"eacces", b"operation not permitted", b"permission denied")
# Per cause, in order: markers that name the cause alone, then words that name
# it on a line that also holds a denial word.
CAUSES = (
    # A daemon that is merely down prints the same text, so Docker needs a denial word on the line.
    (DOCKER_NOTE, (), (b"docker daemon",)),
    (
        PTY_NOTE,
        (b"out of pty devices",),
        (b"/dev/ptmx", b"openpty", b"forkpty", b"posix_openpt"),
    ),
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


# Addresses that make a blocked connection one to this machine.
LOOPBACK_MARKERS = (b"127.0.0.1", b"localhost", b"::1")


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


def _holds_address(line: bytes, marker: bytes) -> bool:
    """Like `_holds`, but `::1` may not continue another IPv6 address such as `fe80::1`."""
    ipv6 = marker.startswith(b":")
    start = line.find(marker)
    while start >= 0:
        end = start + len(marker)
        before = line[start - 1] if start else None
        clear_start = before is None or not (
            _word_byte(before) or (ipv6 and (before == ord(":") or chr(before) in "0123456789abcdef"))
        )
        after = line[end] if end < len(line) else None
        clear_end = after is None or not _word_byte(after)
        # A bracketed address must close right after the marker.
        if ipv6 and before == ord("["):
            clear_end = after == ord("]")
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


def loopback_denied(outputs: Iterable[bytes]) -> bool:
    """Whether a line of `outputs` names a blocked connection to this machine."""
    return any(
        _line_note(line) == CONNECT_NOTE and any(_holds_address(line, marker) for marker in LOOPBACK_MARKERS)
        for output in outputs
        for line in output.lower().split(b"\n")
    )
