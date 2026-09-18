"""Scan-scoped, bounded Git object reads using immutable object identifiers.

Only hexadecimal OIDs enter the batch protocol. Paths (including newlines) are
decoded separately from Git's NUL-delimited raw diff. A metadata stream admits
the object before the content stream is asked to materialize it. Both streams
are read-only, suppress replacement objects and are closed with their scan.
"""

from __future__ import annotations

import hashlib
import os
import queue
import re
import subprocess
import threading
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, final

_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HEADER_BYTES = 256
_CACHE_ENTRIES = 1_024


class GitObjectReadError(RuntimeError):
    """An object could not be read completely; messages contain no object data."""


@dataclass(frozen=True, slots=True)
class GitBlobReference:
    path: str
    oid: str


def parse_raw_diff(data: bytes) -> list[GitBlobReference] | None:
    """Parse ``--raw --no-abbrev --no-renames -z`` output without quoting paths."""

    if not data:
        return []
    parts = data.split(b"\0")
    if parts.pop() != b"" or len(parts) % 2:
        return None
    blobs: list[GitBlobReference] = []
    for offset in range(0, len(parts), 2):
        header, path = parts[offset : offset + 2]
        fields = header.split(b" ")
        if len(fields) != 5 or not fields[0].startswith(b":") or not path:
            return None
        try:
            oid = fields[3].decode("ascii")
            mode = int(fields[1], 8)
        except (UnicodeError, ValueError):
            return None
        if _OID.fullmatch(oid) is None or fields[4] not in {b"A", b"C", b"M", b"T", b"D"}:
            return None
        # Deleted entries have no content. Keep gitlinks so callers preserve
        # their existing non-blob coverage policy (staged: incomplete; history:
        # skipped). Symlink target bytes are blobs, as in the existing scanner.
        if mode == 0:
            continue
        if mode not in {0o100644, 0o100755, 0o120000, 0o160000}:
            return None
        blobs.append(GitBlobReference(path.decode("utf-8", errors="surrogateescape"), oid))
    return blobs


def _read_exact(stream: IO[bytes], size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise GitObjectReadError("git_object_short_read")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@final
class _BatchProcess:
    """One serial stream with a portable deadline covering writes and reads.

    Pipe selectors are not portable to Windows. A single worker thread per
    stream performs blocking I/O; the caller kills the child on timeout, which
    releases the pipe and the thread. No per-object process or thread is made.
    """

    def __init__(self, root: Path, *, contents: bool, timeout: float) -> None:
        self._contents = contents
        self._timeout = timeout
        self._closed = threading.Event()
        self._requests: queue.Queue[tuple[str, int | None] | None] = queue.Queue(maxsize=1)
        self._responses: queue.Queue[int | bytes | None | Exception] = queue.Queue(maxsize=1)
        self._process: subprocess.Popen[bytes] = subprocess.Popen(
            ["git", "--no-replace-objects", "-C", str(root), "cat-file", "--batch" if contents else "--batch-check"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        )
        self._thread = threading.Thread(target=self._serve, name="guard-git-object-reader", daemon=True)
        try:
            self._thread.start()
        except RuntimeError:
            self._process.kill()
            _ = self._process.wait(timeout=2)
            for stream in (self._process.stdin, self._process.stdout):
                if stream is not None:
                    stream.close()
            raise GitObjectReadError("git_object_reader_start_failed") from None

    def _serve(self) -> None:
        while not self._closed.is_set():
            request = self._requests.get()
            if request is None:
                return
            try:
                value = self._exchange(*request)
            except (OSError, ValueError, GitObjectReadError) as error:
                value = error
            self._responses.put(value)

    def _exchange(self, oid: str, expected_size: int | None) -> int | bytes | None:
        assert self._process.stdin is not None and self._process.stdout is not None
        request = (oid + "\n").encode("ascii")
        if self._process.stdin.write(request) != len(request):
            raise GitObjectReadError("git_object_short_write")
        self._process.stdin.flush()
        header: bytes = self._process.stdout.readline(_HEADER_BYTES + 1)
        if len(header) > _HEADER_BYTES or not header.endswith(b"\n"):
            raise GitObjectReadError("git_object_invalid_header")
        parts = header[:-1].split(b" ")
        if parts == [oid.encode("ascii"), b"missing"]:
            raise GitObjectReadError("git_object_missing")
        if len(parts) != 3 or parts[0] != oid.encode("ascii") or not parts[2].isdigit():
            raise GitObjectReadError("git_object_invalid_header")
        size = int(parts[2])
        if not self._contents:
            return size if parts[1] == b"blob" else None
        if parts[1] != b"blob" or size != expected_size:
            raise GitObjectReadError("git_object_identity_changed")
        data = _read_exact(self._process.stdout, size)
        if _read_exact(self._process.stdout, 1) != b"\n":
            raise GitObjectReadError("git_object_invalid_terminator")
        # Match Git's stored object format; this checksum does not authenticate
        # a publisher or grant trust. The returned bytes still undergo scanning.
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        digest = hashlib.sha1(usedforsecurity=False) if len(oid) == 40 else hashlib.sha256()
        digest.update(f"blob {size}\0".encode("ascii"))
        digest.update(data)
        if digest.hexdigest() != oid:
            raise GitObjectReadError("git_object_digest_mismatch")
        return data

    def request(self, oid: str, expected_size: int | None = None) -> int | bytes | None:
        if self._closed.is_set() or _OID.fullmatch(oid) is None:
            raise GitObjectReadError("git_object_reader_unavailable")
        self._requests.put_nowait((oid, expected_size))
        try:
            response = self._responses.get(timeout=self._timeout)
        except queue.Empty:
            self.close()
            raise GitObjectReadError("git_object_timeout") from None
        if isinstance(response, Exception):
            self.close()
            raise GitObjectReadError("git_object_read_failed") from None
        return response

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        if self._process.poll() is None:
            with suppress(ProcessLookupError):
                self._process.kill()
        _ = self._process.wait(timeout=2)
        with suppress(queue.Full):
            self._requests.put_nowait(None)
        self._thread.join(timeout=2)
        for stream in (self._process.stdin, self._process.stdout):
            if stream is not None:
                stream.close()


@final
class GitObjectReader:
    """Lazily own at most two cat-file children for a whole scan."""

    def __init__(self, root: Path, *, timeout: float = 20) -> None:
        self._root = root
        self._timeout = timeout
        self._metadata: _BatchProcess | None = None
        self._contents: _BatchProcess | None = None
        self._sizes: OrderedDict[str, int | None] = OrderedDict()

    def __enter__(self) -> GitObjectReader:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def size(self, oid: str) -> int | None:
        if oid in self._sizes:
            self._sizes.move_to_end(oid)
            return self._sizes[oid]
        if self._metadata is None:
            self._metadata = _BatchProcess(self._root, contents=False, timeout=self._timeout)
        result = self._metadata.request(oid)
        assert isinstance(result, int) or result is None
        self._sizes[oid] = result
        if len(self._sizes) > _CACHE_ENTRIES:
            _ = self._sizes.popitem(last=False)
        return result

    def read(self, oid: str, *, size: int, max_bytes: int) -> bytes:
        if size < 0 or size > max_bytes or self.size(oid) != size:
            raise GitObjectReadError("git_object_size_not_admitted")
        if self._contents is None:
            self._contents = _BatchProcess(self._root, contents=True, timeout=self._timeout)
        result = self._contents.request(oid, size)
        assert isinstance(result, bytes)
        return result

    def close(self) -> None:
        for process in (self._metadata, self._contents):
            if process is not None:
                process.close()
        self._sizes.clear()
