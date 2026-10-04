"""Export and import bounded public evidence without raw prompts or executable files."""

from __future__ import annotations

import hashlib
import io
import re
import stat
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXTRACTED = 64 * 1024 * 1024
CASE_PATH = re.compile(r"cases/[a-z][a-z0-9-]{0,79}\.json")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Refuse redirects while downloading public evidence archives."""
        return None


def allowed_name(name: str) -> bool:
    """Only the public summary and case JSON belong in a qualification bundle."""
    return name in {"summary.json", "summary.md"} or CASE_PATH.fullmatch(name) is not None


def pack(directory: Path, output: Path) -> str:
    """Package public evidence only; verification is a separate mandatory step."""
    directory = directory.resolve()
    paths = sorted(p for p in directory.rglob("*") if p.is_file())
    if not paths or any(p.is_symlink() or not allowed_name(p.relative_to(directory).as_posix()) for p in paths):
        raise ValueError("evidence directory contains missing, private or unexpected files")
    if sum(p.stat().st_size for p in paths) > MAX_EXTRACTED:
        raise ValueError("evidence directory exceeds the public export budget")
    with output.open("xb") as destination, zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, path.relative_to(directory).as_posix())
    if output.stat().st_size > MAX_ARCHIVE:
        raise ValueError("compressed evidence exceeds its transport budget")
    return hashlib.sha256(output.read_bytes()).hexdigest()


def unpack(data: bytes, directory: Path, expected_sha256: str) -> None:
    """Reject path traversal, duplicates, symlinks, executable payloads and zip bombs."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("a full SHA-256 digest is required")
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("evidence archive digest or size does not match")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > 256 or len(names) != len(set(names)) or "summary.json" not in names:
            raise ValueError("missing summary, duplicate entries or oversized evidence inventory")
        if sum(entry.file_size for entry in entries) > MAX_EXTRACTED:
            raise ValueError("evidence expands beyond the extraction budget")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in entry.filename
                or not allowed_name(entry.filename)
                or stat.S_ISLNK(mode)
                or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
                or entry.flag_bits & 1
            ):
                raise ValueError("unsafe or unexpected evidence archive entry")
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        for entry in entries:
            path = directory / entry.filename
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(entry) as source, path.open("xb") as output:
                remaining = entry.file_size
                while remaining:
                    chunk = source.read(min(remaining, 65536))
                    if not chunk:
                        raise ValueError("truncated evidence archive entry")
                    output.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise ValueError("evidence entry exceeds declared size")


def download(url: str) -> bytes:
    """Fetch a direct signed object URL without sending GitHub credentials."""
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    allowed = (
        host.endswith(".r2.cloudflarestorage.com")
        or host.endswith(".amazonaws.com")
        or host.endswith(".blob.core.windows.net")
        or host == "objects.githubusercontent.com"
    )
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in {None, 443}
        or not allowed
    ):
        raise ValueError("use a direct HTTPS R2, S3, Azure artifact or GitHub object URL")
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(url, headers={"Accept": "application/zip"}), timeout=60) as response:
        if response.status != 200:
            raise ValueError("evidence object download failed")
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("evidence object exceeds its transport budget")
    return data
