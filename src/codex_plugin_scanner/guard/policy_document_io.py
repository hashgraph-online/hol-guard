"""Trusted policy file I/O and backwards-compatible policy adapters."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Final, final

from .policy_document import GuardPolicyDocument
from .policy_document_compile import build_policy_document_from_rows, compile_policy_document
from .policy_document_diff import diff_policy_documents
from .policy_document_types import CompiledPolicyRow, PolicyCompilationError, PolicyDocumentDiff
from .policy_document_yaml import (
    MAX_POLICY_BYTES,
    format_policy_document_yaml,
    parse_policy_document_yaml,
)

_POLICY_FILE_MODE: Final = 0o600
_POLICY_DIRECTORY_MODE_MASK: Final = 0o022


@final
class PolicyFileTrustError(ValueError):
    """Raised when a policy path cannot be trusted for local I/O."""

    def __init__(self, code: str, path: Path) -> None:
        self.code = code
        self.path = path
        super().__init__(code)


def _assert_trusted_parent_metadata(path: Path, metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PolicyFileTrustError("policy_parent_not_directory", path)
    if metadata.st_uid != os.geteuid():
        raise PolicyFileTrustError("policy_parent_not_owned", path)
    if stat.S_IMODE(metadata.st_mode) & _POLICY_DIRECTORY_MODE_MASK:
        raise PolicyFileTrustError("policy_parent_insecure_mode", path)


def _open_trusted_parent(path: Path) -> int:
    parent = path.parent
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        parts = parent.parts
        if not parts:
            raise OSError("policy parent has no path components")
        descriptor = os.open(parts[0], flags)
        for component in parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        _assert_trusted_parent_metadata(parent, os.fstat(descriptor))
        return descriptor
    except PolicyFileTrustError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise PolicyFileTrustError("policy_parent_unavailable", parent) from error


def _assert_trusted_file_metadata(path: Path, metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyFileTrustError("policy_file_not_regular", path)
    if metadata.st_uid != os.geteuid():
        raise PolicyFileTrustError("policy_file_not_owned", path)
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PolicyFileTrustError("policy_file_insecure_mode", path)
    if metadata.st_nlink != 1:
        raise PolicyFileTrustError("policy_file_link_count", path)


def read_trusted_policy_bytes(path: Path, *, max_bytes: int = MAX_POLICY_BYTES) -> bytes:
    """Read one bounded, owner-only regular file without following links."""

    candidate = path.expanduser().absolute()
    parent_descriptor = _open_trusted_parent(candidate)
    try:
        try:
            before = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise PolicyFileTrustError("policy_file_unavailable", candidate) from error
        _assert_trusted_file_metadata(candidate, before)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        except OSError as error:
            raise PolicyFileTrustError("policy_file_open_failed", candidate) from error
        try:
            opened = os.fstat(descriptor)
            _assert_trusted_file_metadata(candidate, opened)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise PolicyFileTrustError("policy_file_changed", candidate)
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) > max_bytes:
                raise PolicyFileTrustError("policy_file_too_large", candidate)
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def read_trusted_policy_text(path: Path, *, max_bytes: int = MAX_POLICY_BYTES) -> str:
    payload = read_trusted_policy_bytes(path, max_bytes=max_bytes)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyFileTrustError("policy_file_not_utf8", path.expanduser().absolute()) from error


def write_private_policy_text(path: Path, content: str) -> None:
    """Atomically replace an owner-only policy file inside a private directory."""

    candidate = path.expanduser().absolute()
    payload = content.encode("utf-8")
    if len(payload) > MAX_POLICY_BYTES:
        raise PolicyFileTrustError("policy_output_too_large", candidate)
    parent_descriptor = _open_trusted_parent(candidate)
    temporary_name = f".{candidate.name}.{secrets.token_hex(12)}.tmp"
    descriptor: int | None = None
    try:
        try:
            existing = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        except OSError as error:
            raise PolicyFileTrustError("policy_output_unavailable", candidate) from error
        if existing is not None:
            _assert_trusted_file_metadata(candidate, existing)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            temporary_name,
            flags,
            _POLICY_FILE_MODE,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, _POLICY_FILE_MODE)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("policy output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            candidate.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    except PolicyFileTrustError:
        raise
    except OSError as error:
        raise PolicyFileTrustError("policy_output_write_failed", candidate) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        os.close(parent_descriptor)


def load_trusted_policy_document(path: Path) -> GuardPolicyDocument:
    return parse_policy_document_yaml(read_trusted_policy_text(path))


def format_trusted_policy_file(source: Path, destination: Path) -> GuardPolicyDocument:
    document = load_trusted_policy_document(source)
    write_private_policy_text(destination, format_policy_document_yaml(document))
    return document


__all__ = (
    "CompiledPolicyRow",
    "PolicyCompilationError",
    "PolicyDocumentDiff",
    "PolicyFileTrustError",
    "build_policy_document_from_rows",
    "compile_policy_document",
    "diff_policy_documents",
    "format_trusted_policy_file",
    "load_trusted_policy_document",
    "read_trusted_policy_bytes",
    "read_trusted_policy_text",
    "write_private_policy_text",
)
