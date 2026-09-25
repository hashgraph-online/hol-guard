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
    if not _private_recovery_parent(canonical_parent):
        raise _CliError(
            "recovery_path_invalid",
            "evaluation recovery parent is not a private directory",
            status="blocked_environment",
        )
    return canonical_parent / f"{_RECOVERY_TOKEN_PREFIX}{owned_root.name}{_RECOVERY_TOKEN_SUFFIX}"


def _validate_recovery_token_file(token_path: Path, *, expected_parent: Path) -> None:
    try:
        if token_path.parent != expected_parent or token_path.is_symlink() or not token_path.is_file():
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
        details = token_path.stat()
        if not stat.S_ISREG(details.st_mode):
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
        valid_access = os.name != "nt" and details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) == 0o600
        if not valid_access:
            raise _CliError(
                "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
            )
    except (OSError, RuntimeError, ValueError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None


def _write_recovery_token(setup: EvaluationSetup, *, declared_parent: Path) -> None:
    if setup.root_path is None or setup.marker_token is None:
        raise _CliError("cleanup_token_unavailable", "evaluation setup did not produce a cleanup token")
    token_path = _recovery_token_path(setup.root_path, declared_parent=declared_parent)
    descriptor: int | None = None
    created = False
    completed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(os.fspath(token_path), flags, 0o600)
        created = True
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or (
            os.name != "nt" and (details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) != 0o600)
        ):
            raise OSError("recovery token file ownership or mode is unsafe")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(setup.marker_token.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        _validate_recovery_token_file(token_path, expected_parent=token_path.parent)
        completed = True
    except (OSError, UnicodeError, ValueError):
        raise _CliError("cleanup_token_unavailable", "unable to retain the private cleanup token") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created and not completed:
            with contextlib.suppress(OSError, RuntimeError, ValueError):
                token_path.unlink()


def _read_recovery_token(owned_root: Path, *, declared_parent: Path) -> str:
    try:
        token_path = _recovery_token_path(owned_root, declared_parent=declared_parent)
        if not token_path.exists() and not token_path.is_symlink():
            raise _CliError(
                "recovery_token_missing", "evaluation recovery token is missing", status="blocked_environment"
            )
        _validate_recovery_token_file(token_path, expected_parent=token_path.parent)
        descriptor = os.open(os.fspath(token_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except _CliError:
        raise
    except FileNotFoundError:
        raise _CliError(
            "recovery_token_missing", "evaluation recovery token is missing", status="blocked_environment"
        ) from None
    except (OSError, RuntimeError, ValueError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(_MAX_RECOVERY_TOKEN_BYTES + 1)
    except (OSError, ValueError):
        raise _CliError(
            "recovery_token_invalid", "evaluation recovery token is invalid", status="blocked_environment"
        ) from None
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
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
    _validate_recovery_token_file(token_path, expected_parent=expected_parent)
    try:
        token_path.unlink()
    except (OSError, RuntimeError, ValueError):
        raise _CliError(
            "cleanup_failed", "unable to remove the private cleanup token", status="blocked_environment"
        ) from None
