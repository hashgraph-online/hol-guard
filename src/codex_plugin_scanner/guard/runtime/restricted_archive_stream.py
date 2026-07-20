"""Bounded response validation and immutable archive-blob streaming."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import urllib.parse
from contextlib import suppress
from pathlib import Path

from .restricted_archive_contract import (
    RestrictedArchiveDownload,
    _ReadableResponse,
    _RestrictedDownloadError,
)
from .restricted_archive_deadline import _call_with_deadline, _remaining_seconds

_READ_CHUNK_BYTES = 64 * 1024
_MAX_RESPONSE_HEADERS = 64
_MAX_RESPONSE_HEADER_BYTES = 32 * 1024
_HTTP_FIELD_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _response_header(response: _ReadableResponse, name: str) -> str | None:
    return response.get_header(name)


def _validate_response_headers(response: _ReadableResponse) -> None:
    headers = response.header_items()
    if len(headers) > _MAX_RESPONSE_HEADERS:
        raise _RestrictedDownloadError(
            "external_archive_response_headers_invalid",
            "External archive response headers were malformed or exceeded Guard's limit.",
        )
    total_bytes = 0
    for name, value in headers:
        if not _HTTP_FIELD_NAME_RE.fullmatch(name) or any(
            (ord(character) < 0x20 and character != "\t") or ord(character) == 0x7F for character in value
        ):
            raise _RestrictedDownloadError(
                "external_archive_response_headers_invalid",
                "External archive response headers were malformed or exceeded Guard's limit.",
            )
        total_bytes += len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
        if total_bytes > _MAX_RESPONSE_HEADER_BYTES:
            raise _RestrictedDownloadError(
                "external_archive_response_headers_invalid",
                "External archive response headers were malformed or exceeded Guard's limit.",
            )


def _content_length(response: _ReadableResponse, *, max_bytes: int) -> int | None:
    raw_length = _response_header(response, "Content-Length")
    if raw_length is None:
        return None
    try:
        content_length = int(raw_length, 10)
    except ValueError:
        raise _RestrictedDownloadError(
            "external_archive_incomplete_response",
            "External archive response declared an invalid content length.",
        ) from None
    if content_length < 0:
        raise _RestrictedDownloadError(
            "external_archive_incomplete_response",
            "External archive response declared an invalid content length.",
        )
    if content_length > max_bytes:
        raise _RestrictedDownloadError(
            "external_archive_download_size_limit",
            "External archive exceeded Guard's download size limit.",
        )
    return content_length


def _write_chunk_with_deadline(file_descriptor: int, chunk: bytes, *, deadline: float) -> None:
    offset = 0
    while offset < len(chunk):
        pending = memoryview(chunk)[offset:]
        written = _call_with_deadline(
            lambda pending=pending: os.write(file_descriptor, pending),
            deadline=deadline,
        )
        if written <= 0:
            raise _RestrictedDownloadError(
                "external_archive_connection_failed",
                "External archive temporary blob could not be written completely.",
            )
        offset += written


def _write_bounded_response(
    response: _ReadableResponse,
    *,
    source_url: str,
    final_url: str,
    deadline: float,
    max_bytes: int,
    temp_dir: Path | None,
) -> RestrictedArchiveDownload:
    content_encoding = (_response_header(response, "Content-Encoding") or "identity").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise _RestrictedDownloadError(
            "external_archive_content_encoding_rejected",
            "External archive response used an unsupported content encoding.",
        )
    expected_size = _content_length(response, max_bytes=max_bytes)
    directory = str(temp_dir) if temp_dir is not None else None
    source_path = urllib.parse.urlsplit(source_url).path.lower()
    suffix = next(
        (candidate for candidate in (".tar.gz", ".tgz", ".tar") if source_path.endswith(candidate)),
        ".archive",
    )
    file_descriptor, raw_path = tempfile.mkstemp(prefix="hol-guard-archive-", suffix=suffix, dir=directory)
    path = Path(raw_path)
    digest = hashlib.sha256()
    size = 0
    try:
        _ = _remaining_seconds(deadline)
        path = path.resolve(strict=True)
        while True:
            response.set_timeout(_remaining_seconds(deadline))
            # Keep one byte of overflow probe capacity. Reading exactly the
            # configured limit cannot distinguish a complete body from a body
            # with an additional byte until EOF or that probe is observed.
            remaining_with_probe = max_bytes - size + 1
            chunk = response.read(min(_READ_CHUNK_BYTES, remaining_with_probe))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise _RestrictedDownloadError(
                    "external_archive_download_size_limit",
                    "External archive exceeded Guard's download size limit.",
                )
            _write_chunk_with_deadline(file_descriptor, chunk, deadline=deadline)
            digest.update(chunk)
            _ = _remaining_seconds(deadline)
        if expected_size is not None and size != expected_size:
            raise _RestrictedDownloadError(
                "external_archive_incomplete_response",
                "External archive response ended before its declared content length.",
            )
        os.fchmod(file_descriptor, 0o400)
        _ = _remaining_seconds(deadline)
        os.close(file_descriptor)
        file_descriptor = -1
        return RestrictedArchiveDownload(
            path=path,
            sha256=digest.hexdigest(),
            size=size,
            source_url=source_url,
            final_url=final_url,
        )
    except BaseException:
        with suppress(OSError):
            path.unlink()
        raise
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
