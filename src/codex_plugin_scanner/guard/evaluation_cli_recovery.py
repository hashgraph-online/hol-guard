"""Private recovery-token storage for the staged evaluation CLI."""

from __future__ import annotations

import contextlib
import os
import re
import stat
from pathlib import Path

from .evaluation_preflight import EvaluationSetup

_MAX_RECOVERY_TOKEN_BYTES = 128
_RECOVERY_TOKEN_PREFIX = ".hol-guard-evaluation-recovery-"
_RECOVERY_TOKEN_SUFFIX = ".token"
_RECOVERY_TOKEN_PATTERN = re.compile(r"[0-9a-f]{32}")

__all__ = [
    "_CliError",
    "_read_recovery_token",
    "_recovery_token_path",
    "_remove_recovery_token",
    "_write_recovery_token",
]


class _CliError(ValueError):
    """An expected input or environment failure with a stable public code."""

    code: str
    message: str
    status: str

    def __init__(self, code: str, message: str, *, status: str = "not_run") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _private_recovery_parent(path: Path) -> bool:
    try:
        if "\x00" in os.fspath(path) or path.is_symlink() or not path.is_dir():
            return False
        details = path.stat()
        if not stat.S_ISDIR(details.st_mode):
            return False
        if os.name == "nt":
            return False
        return details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) & 0o077 == 0
    except (OSError, RuntimeError, ValueError):
        return False


def _recovery_token_path(owned_root: Path, *, declared_parent: Path | None = None) -> Path:
    if not owned_root.is_absolute() or not owned_root.name.startswith("hol-guard-eval-"):
        raise _CliError("recovery_path_invalid", "evaluation recovery path is invalid", status="blocked_environment")
    parent = owned_root.parent
    if declared_parent is not None:
        try:
            same_parent = os.path.normcase(os.path.realpath(parent)) == os.path.normcase(
                os.path.realpath(declared_parent)
            )
        except (OSError, RuntimeError, ValueError):
            same_parent = False
        if not same_parent:
            raise _CliError(
                "recovery_path_invalid",
                "evaluation recovery path is outside the profile target scope",
                status="blocked_environment",
            )
    if not _private_recovery_parent(parent):
        raise _CliError(
            "recovery_path_invalid",
            "evaluation recovery parent is not a private directory",
            status="blocked_environment",
        )
    canonical_parent = Path(os.path.realpath(parent))
    return canonical_parent / f"{_RECOVERY_TOKEN_PREFIX}{owned_root.name}{_RECOVERY_TOKEN_SUFFIX}"


def _open_private_recovery_parent(parent: Path) -> int:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise _CliError(
            "recovery_path_invalid", "private recovery parent access is unavailable", status="blocked_environment"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(os.fspath(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o077:
            raise OSError("recovery parent ownership or mode is unsafe")
        return descriptor
    except (OSError, RuntimeError, ValueError):
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise _CliError(
            "recovery_path_invalid",
            "evaluation recovery parent is not a private directory",
            status="blocked_environment",
        ) from None


def _private_recovery_token(details: os.stat_result) -> bool:
    return (
        os.name != "nt"
        and stat.S_ISREG(details.st_mode)
        and details.st_uid == os.getuid()
        and stat.S_IMODE(details.st_mode) == 0o600
    )


def _write_recovery_token(setup: EvaluationSetup, *, declared_parent: Path) -> None:
    if setup.root_path is None or setup.marker_token is None:
        raise _CliError("cleanup_token_unavailable", "evaluation setup did not produce a cleanup token")
    token_path = _recovery_token_path(setup.root_path, declared_parent=declared_parent)
    parent_descriptor = _open_private_recovery_parent(token_path.parent)
    descriptor: int | None = None
    created = False
    completed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(token_path.name, flags, 0o600, dir_fd=parent_descriptor)
        created = True
        created_details = os.fstat(descriptor)
        if not _private_recovery_token(created_details):
            raise OSError("recovery token file ownership or mode is unsafe")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(setup.marker_token.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        actual_details = os.stat(token_path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not _private_recovery_token(actual_details) or (
            actual_details.st_dev,
            actual_details.st_ino,
        ) != (created_details.st_dev, created_details.st_ino):
            raise OSError("recovery token changed during write")
        completed = True
    except (OSError, UnicodeError, ValueError, TypeError, NotImplementedError):
        raise _CliError("cleanup_token_unavailable", "unable to retain the private cleanup token") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created and not completed:
            with contextlib.suppress(OSError, RuntimeError, ValueError):
                os.unlink(token_path.name, dir_fd=parent_descriptor)
        with contextlib.suppress(OSError):
            os.close(parent_descriptor)


def _read_recovery_token(owned_root: Path, *, declared_parent: Path) -> str:
    token_path = _recovery_token_path(owned_root, declared_parent=declared_parent)
    parent_descriptor = _open_private_recovery_parent(token_path.parent)
    descriptor: int | None = None
    try:
        descriptor = os.open(token_path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor)
        if not _private_recovery_token(os.fstat(descriptor)):
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read(_MAX_RECOVERY_TOKEN_BYTES + 1)
    except _CliError:
        raise
    except FileNotFoundError:
        raise _CliError(
            "recovery_token_missing", "evaluation recovery token is missing", status="blocked_environment"
        ) from None
    except (OSError, RuntimeError, ValueError, TypeError, NotImplementedError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            os.close(parent_descriptor)
    if len(data) > _MAX_RECOVERY_TOKEN_BYTES:
        raise _CliError("recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment")
    try:
        token = data.decode("ascii")
    except UnicodeDecodeError:
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    if _RECOVERY_TOKEN_PATTERN.fullmatch(token) is None:
        raise _CliError("recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment")
    return token


def _remove_recovery_token(token_path: Path, *, expected_parent: Path) -> None:
    if token_path.parent != expected_parent:
        raise _CliError(
            "recovery_path_invalid",
            "evaluation recovery path is outside the profile target scope",
            status="blocked_environment",
        )
    parent_descriptor = _open_private_recovery_parent(expected_parent)
    try:
        try:
            details = os.stat(token_path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if not _private_recovery_token(details):
                raise OSError("recovery token ownership or mode is unsafe")
        except (OSError, RuntimeError, ValueError, TypeError, NotImplementedError):
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            ) from None
        try:
            os.unlink(token_path.name, dir_fd=parent_descriptor)
        except (OSError, RuntimeError, ValueError, TypeError, NotImplementedError):
            raise _CliError(
                "cleanup_failed", "unable to remove the private cleanup token", status="blocked_environment"
            ) from None
    finally:
        with contextlib.suppress(OSError):
            os.close(parent_descriptor)
