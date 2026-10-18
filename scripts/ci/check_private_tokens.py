"""Fail when tracked files or commit messages contain a runner-supplied private token.

The denylist is never committed: it comes from ``GUARD_PRIVATE_TOKEN_DENYLIST`` in the
runner environment (newline- or comma-separated, case-insensitive). When it is unset or
empty the check is skipped. Matches are reported by location and the entry's position in
the denylist, so the log never repeats a private token.

Every tracked file is searched as raw bytes, in chunks, whatever its size or type, and a
file that cannot be read is a finding: nothing is skipped silently.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import BinaryIO

ENV_NAMES = ("GUARD_PRIVATE_TOKEN_DENYLIST", "GUARD_PRIVATE_TOKEN_DENYLIST_SECRET")
CHUNK_BYTES = 1024 * 1024
MIN_TOKEN_CHARS = 3

# A denylist entry: its 1-based position in the secret, then the lowercased token.
Entry = tuple[int, str]


def load_denylist(environ: Mapping[str, str] | None = None) -> list[Entry]:
    """Entries from the first variable that holds any, each keeping its position in the secret.

    Tokens shorter than ``MIN_TOKEN_CHARS`` are ignored to avoid noise, and a repeated token
    is reported under the position where it first appears.
    """
    environ = os.environ if environ is None else environ
    for name in ENV_NAMES:
        lines = environ.get(name, "").replace(",", "\n").splitlines()
        entries: dict[str, int] = {}
        for position, line in enumerate(lines, start=1):
            token = line.strip().lower()
            if len(token) >= MIN_TOKEN_CHARS:
                entries.setdefault(token, position)
        if entries:
            return [(position, token) for token, position in entries.items()]
    return []


def _needles(token: str) -> set[bytes]:
    """Byte forms of one token, ASCII-lowered to meet ASCII-lowered content."""
    return {form.encode("utf-8").lower() for form in (token, token.upper(), token.casefold())}


def _matches(text: str, entries: list[Entry]) -> list[int]:
    lowered = text.lower()
    return [position for position, token in entries if token in lowered]


def scan_stream(label: str, stream: BinaryIO, entries: list[Entry]) -> list[str]:
    """Findings for one byte stream, naming the line and entry, never the token."""
    needles = [(position, needle) for position, token in entries for needle in _needles(token)]
    if not needles:
        return []
    overlap = max(len(needle) for _, needle in needles) - 1
    hits: set[tuple[int, int]] = set()
    carry = b""
    line = 1  # the line number at the first byte of ``carry``
    while chunk := stream.read(CHUNK_BYTES):
        window = carry + chunk
        lowered = window.lower()
        for position, needle in needles:
            start = lowered.find(needle)
            while start != -1:
                hits.add((line + window.count(b"\n", 0, start), position))
                start = lowered.find(needle, start + 1)
        keep_from = max(len(window) - overlap, 0)
        line += window.count(b"\n", 0, keep_from)
        carry = window[keep_from:]
    return [f"{label}:{number}: matches private denylist entry #{entry}" for number, entry in sorted(hits)]


def scan_text(label: str, text: str, entries: list[Entry]) -> list[str]:
    """Findings for one text blob."""
    return scan_stream(label, io.BytesIO(text.encode("utf-8", "surrogateescape")), entries)


def tracked_files(root: Path) -> list[str]:
    """Every path git tracks under ``root``."""
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True, timeout=120
    ).stdout.decode("utf-8", "surrogateescape")
    return [name for name in output.split("\0") if name]


def commit_messages(root: Path, revision_range: str) -> Iterable[tuple[str, bytes]]:
    """Short SHA and raw message for each commit in the range.

    ``-z`` ends every record with NUL, which git refuses inside a message, so a message can
    never end its own record early. An unpaired field is an error, not a shorter scan.
    """
    output = subprocess.run(
        ["git", "log", "-z", "--format=%H%x00%B", revision_range],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=120,
    ).stdout
    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise RuntimeError("git log returned an unpaired commit record")
    for sha, body in zip(fields[0::2], fields[1::2], strict=True):
        yield sha.decode("ascii", "replace")[:12], body


def _scan_path(label: str, path: Path, entries: list[Entry]) -> list[str]:
    """A tracked file's bytes, or a symlink's target text; a file that cannot be read is a finding."""
    try:
        if path.is_symlink():
            return scan_stream(label, io.BytesIO(os.readlink(path).encode("utf-8", "surrogateescape")), entries)
        if not path.is_file():
            return []  # a submodule or other non-file entry has no tracked bytes here
        with path.open("rb") as handle:
            return scan_stream(label, handle, entries)
    except OSError as error:
        return [f"{label}: could not be scanned ({type(error).__name__})"]


def scan(root: Path, tokens: list[Entry], revision_range: str | None) -> list[str]:
    """Findings across tracked paths, every tracked file and, optionally, commit messages."""
    findings: list[str] = []
    for index, name in enumerate(tracked_files(root), start=1):
        # A path can itself carry the token; then it is named by position, not spelled out.
        label = f"tracked file #{index}" if _matches(name, tokens) else name
        if label != name:
            findings.append(f"{label}: path matches a private denylist entry")
        findings.extend(_scan_path(label, root / name, tokens))
    if revision_range:
        for sha, body in commit_messages(root, revision_range):
            findings.extend(scan_stream(f"commit {sha} message", io.BytesIO(body), tokens))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--range", dest="revision_range", help="Also scan commit messages in this git range")
    args = parser.parse_args(argv)
    tokens = load_denylist()
    if not tokens:
        print("private-token check skipped: GUARD_PRIVATE_TOKEN_DENYLIST is not set")
        return 0
    findings = scan(args.root.resolve(), tokens, args.revision_range)
    for finding in findings:
        print(finding)
    if findings:
        print(f"private-token check failed: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print(f"private-token check passed against {len(tokens)} denylist entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
