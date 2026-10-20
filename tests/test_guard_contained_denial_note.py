"""The note a failed workspace-contained run gets names what the sandbox blocked."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_denial_note as notes
from codex_plugin_scanner.guard.runtime.contained_denial_note import denial_note

_RUST = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/contained_workspace_sink_denial.rs"
_NOTE_NAMES = ("WRITE_NOTE", "EXEC_NOTE", "CONNECT_NOTE", "READ_NOTE", "PTY_NOTE", "DOCKER_NOTE", "GENERIC_NOTE")


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (b"Error: EPERM: operation not permitted, mkdir '/opt/lanectl/cache'", notes.WRITE_NOTE),
        (b"OSError: [Errno 30] Read-only file system: 'out'", notes.WRITE_NOTE),
        (b"Error: spawn EACCES", notes.EXEC_NOTE),
        (b"Error: EACCES: permission denied, posix_spawn '/opt/lanectl/bin/lanectl'", notes.EXEC_NOTE),
        (b"Error: EPERM: operation not permitted, mkdir '/usr/libexec/lanectl'", notes.WRITE_NOTE),
        (b"Error: EACCES: permission denied, open '/opt/exec-cache/rewrite.log'", notes.GENERIC_NOTE),
        (b"sh: /opt/lanectl/bin/lanectl: cannot execute binary file", None),
        (b"Error: connect ECONNREFUSED 127.0.0.1:8080", None),
        (b"Error: connect EPERM 203.0.113.7:443", notes.CONNECT_NOTE),
        (b"curl: (6) Could not resolve host: echo-mcp.invalid", notes.CONNECT_NOTE),
        (b"Error: EPERM: operation not permitted, scandir '/home/dev'", notes.READ_NOTE),
        (b"OSError: [Errno 1] Operation not permitted: '/dev/ptmx'", notes.PTY_NOTE),
        (b"OSError: out of pty devices", notes.PTY_NOTE),
        (b"Error: EACCES: permission denied, openpty", notes.PTY_NOTE),
        (
            b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            None,
        ),
        (
            b"permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
            notes.DOCKER_NOTE,
        ),
        (b"OSError: [Errno 1] Operation not permitted: 'data'", notes.GENERIC_NOTE),
        (b"PermissionError: [Errno 13] Permission denied: 'data'", notes.GENERIC_NOTE),
        (b"AssertionError: expected 2, got 3", None),
        ("Error: \u201cEPERM\u201d returned".encode(), notes.GENERIC_NOTE),
    ],
    ids=[
        "mkdir",
        "erofs",
        "spawn",
        "posix-spawn",
        "libexec-path",
        "exec-path",
        "exec-format",
        "refused",
        "connect",
        "resolve",
        "scandir",
        "ptmx",
        "pty-devices",
        "openpty",
        "docker-daemon-down",
        "docker-socket",
        "eperm",
        "eacces",
        "none",
        "non-ascii-neighbour",
    ],
)
def test_each_cause_gets_its_own_note(output: bytes, expected: str | None) -> None:
    assert denial_note([output]) == expected


def test_the_first_line_with_a_cause_picks_the_note() -> None:
    output = b"Error: connect EPERM 127.0.0.1:8080\nError: EROFS: read-only file system"
    assert denial_note([output]) == notes.CONNECT_NOTE
    assert denial_note([b"PermissionError: [Errno 13] Permission denied", b"spawn EPERM"]) == notes.EXEC_NOTE
    assert denial_note([]) is None


def test_every_note_says_what_ran_contained_and_what_runs_directly() -> None:
    for name in _NOTE_NAMES:
        note = getattr(notes, name)
        assert note.endswith(notes.SCOPE)
    assert "children of an interpreter" in notes.SCOPE
    assert "only commands Guard proves safe run directly" in notes.SCOPE
    assert "no PTY" in notes.PTY_NOTE
    assert "Docker" in notes.DOCKER_NOTE
    assert "PTY" in notes.GENERIC_NOTE and "Docker socket" in notes.GENERIC_NOTE


def test_notes_carry_no_link_or_approval_request() -> None:
    for name in _NOTE_NAMES:
        note = getattr(notes, name)
        assert "HOL Guard's workspace sandbox" in note
        assert "http" not in note
        assert "approv" not in note.lower()


def test_rust_keeps_the_same_notes_and_markers_in_the_same_order() -> None:
    source = _RUST.read_text(encoding="utf-8").split("fn holds", 1)[0]
    rust_notes = dict(re.findall(r'const (\w+_NOTE): &str = "((?:[^"\\]|\\.)*)";', source))
    assert rust_notes == {name: getattr(notes, name) for name in _NOTE_NAMES}
    rust_markers = [marker.encode() for marker in re.findall(r'b"((?:[^"\\]|\\.)*)"', source)]
    python_markers = list(notes.DENIAL_WORDS)
    for _, alone, with_denial in notes.CAUSES:
        python_markers.extend((*alone, *with_denial))
    assert rust_markers == python_markers
    rust_order = re.findall(r"\(\s*(\w+_NOTE),", source)
    assert rust_order == [
        next(name for name in _NOTE_NAMES if getattr(notes, name) == cause[0]) for cause in notes.CAUSES
    ]


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (b"Error: connect EPERM 127.0.0.1:8080", True),
        (b"curl: (7) Failed to connect to localhost port 8080: Operation not permitted", True),
        (b"Error: connect EPERM ::1:8080", True),
        (b"Error: connect EPERM [::1]:8080", True),
        (b"Error: connect EPERM ::1", True),
        (b"Error: connect EPERM fe80::1", False),
        (b"Error: connect EPERM 2001:db8::1:443", False),
        (b"Error: connect EPERM ::10:443", False),
        (b"Error: connect EPERM [::1:abcd]:443", False),
        (b"Error: connect EPERM 203.0.113.7:443", False),
        (b"getaddrinfo ENOTFOUND mcp.example.test", False),
        (b"EPERM: operation not permitted, mkdir '/tmp/localhost'", False),
        (b"listening on 127.0.0.1:8080", False),
    ],
)
def test_only_a_blocked_connection_to_this_machine_counts_as_loopback(output: bytes, expected: bool) -> None:
    assert notes.loopback_denied([b"", output]) is expected


def test_rust_keeps_the_same_loopback_markers() -> None:
    source = _RUST.read_text(encoding="utf-8")
    declared = re.search(r"const LOOPBACK_MARKERS: \[&\[u8\]; \d+\] = \[([^\]]*)\];", source)
    assert declared is not None
    rust_markers = tuple(marker.encode() for marker in re.findall(r'b"((?:[^"\\]|\\.)*)"', declared.group(1)))
    assert rust_markers == notes.LOOPBACK_MARKERS
