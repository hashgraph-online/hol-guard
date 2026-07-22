"""Live file and interpreter attestation for Guard-managed Codex hooks.

Authenticated manifests establish the expected hook identity.  This module
describes trusted local files for those manifests and verifies that the live
filesystem still matches the authenticated identity exactly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shlex
import stat
from pathlib import Path


class CodexHookIntegrityError(RuntimeError):
    """One stable, non-secret integrity failure suitable for status output."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def split_hook_command(command: object) -> list[str] | None:
    """Parse one persisted hook command without accepting malformed shell text."""

    if not isinstance(command, str):
        return None
    try:
        return shlex.split(command)
    except ValueError:
        return None


def canonical_path(path: Path) -> str:
    """Return the non-strict canonical absolute spelling used in identities."""

    return str(path.expanduser().resolve(strict=False))


def describe_regular_file(path: Path, *, role: str, executable_required: bool) -> dict[str, object]:
    canonical = Path(canonical_path(path))
    metadata = validate_regular_file(canonical, role=role, executable_required=executable_required)
    return {
        "executable_required": executable_required,
        "mode": stat.S_IMODE(metadata.st_mode),
        "owner_uid": metadata.st_uid if hasattr(metadata, "st_uid") else None,
        "path": str(canonical),
        "role": role,
        "sha256": _sha256_file(canonical),
        "size": metadata.st_size,
    }


def describe_executable_file(path: Path, *, role: str) -> dict[str, object]:
    """Describe an executable invocation and its canonical regular target.

    Virtual-environment interpreters are commonly symlinks.  Executing only the
    resolved target can silently escape that environment, so the manifest binds
    both the absolute invocation path and the canonical target instead.
    """

    invocation = path.expanduser().absolute()
    try:
        invocation_metadata = invocation.lstat()
        target = invocation.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_missing",
            f"The Codex hook {role} is missing; repair the installation.",
        ) from exc
    is_symlink = stat.S_ISLNK(invocation_metadata.st_mode)
    if not is_symlink and not stat.S_ISREG(invocation_metadata.st_mode):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_not_regular",
            f"The Codex hook {role} invocation must be a regular file or symlink to one.",
        )
    if os.name != "nt":
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and invocation_metadata.st_uid not in {current_uid, 0}:
            raise CodexHookIntegrityError(
                f"codex_hook_{role}_owner_untrusted",
                f"The Codex hook {role} invocation has an unexpected owner; repair the installation.",
            )
    if not os.access(invocation, os.X_OK):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_not_executable",
            f"The Codex hook {role} is not executable; repair the installation.",
        )
    link_target = os.readlink(invocation) if is_symlink else None
    return {
        "invocation_mode": stat.S_IMODE(invocation_metadata.st_mode),
        "invocation_owner_uid": invocation_metadata.st_uid if hasattr(invocation_metadata, "st_uid") else None,
        "invocation_path": str(invocation),
        "link_target": link_target,
        "role": role,
        "target": describe_regular_file(target, role=role, executable_required=True),
    }


def verify_regular_file_identity(identity: object) -> None:
    if not isinstance(identity, dict):
        raise CodexHookIntegrityError(
            "codex_hook_file_identity_invalid",
            "The Codex hook manifest has an invalid packaged-file identity; repair the installation.",
        )
    role_value = identity.get("role")
    role = role_value if isinstance(role_value, str) and role_value else "file"
    path_value = identity.get("path")
    digest_value = identity.get("sha256")
    mode_value = identity.get("mode")
    size_value = identity.get("size")
    executable_required = identity.get("executable_required") is True
    if (
        not isinstance(path_value, str)
        or not Path(path_value).is_absolute()
        or not isinstance(digest_value, str)
        or not isinstance(mode_value, int)
        or isinstance(mode_value, bool)
        or not isinstance(size_value, int)
        or isinstance(size_value, bool)
    ):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_identity_invalid",
            f"The Codex hook {role} identity is invalid; repair the installation.",
        )
    path = Path(path_value)
    metadata = validate_regular_file(path, role=role, executable_required=executable_required)
    if canonical_path(path) != path_value:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_path_mismatch",
            f"The Codex hook {role} path is no longer canonical; repair the installation.",
        )
    if stat.S_IMODE(metadata.st_mode) != mode_value:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_mode_mismatch",
            f"The Codex hook {role} permissions changed; repair the installation.",
        )
    if metadata.st_size != size_value or not hmac.compare_digest(_sha256_file(path), digest_value):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_hash_mismatch",
            f"The Codex hook {role} content changed; repair the installation.",
        )
    expected_owner = identity.get("owner_uid")
    if os.name != "nt" and isinstance(expected_owner, int) and metadata.st_uid != expected_owner:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_owner_mismatch",
            f"The Codex hook {role} owner changed; repair the installation.",
        )


def verify_executable_file_identity(identity: object) -> None:
    if not isinstance(identity, dict):
        raise CodexHookIntegrityError(
            "codex_hook_interpreter_identity_invalid",
            "The Codex hook interpreter identity is invalid; repair the installation.",
        )
    role_value = identity.get("role")
    role = role_value if isinstance(role_value, str) and role_value else "interpreter"
    invocation_value = identity.get("invocation_path")
    invocation_mode = identity.get("invocation_mode")
    if (
        not isinstance(invocation_value, str)
        or not Path(invocation_value).is_absolute()
        or not isinstance(invocation_mode, int)
        or isinstance(invocation_mode, bool)
    ):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_identity_invalid",
            f"The Codex hook {role} identity is invalid; repair the installation.",
        )
    invocation = Path(invocation_value)
    try:
        metadata = invocation.lstat()
    except OSError as exc:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_missing",
            f"The Codex hook {role} is missing; repair the installation.",
        ) from exc
    if stat.S_IMODE(metadata.st_mode) != invocation_mode:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_invocation_mode_mismatch",
            f"The Codex hook {role} invocation permissions changed; repair the installation.",
        )
    expected_owner = identity.get("invocation_owner_uid")
    if os.name != "nt" and isinstance(expected_owner, int) and metadata.st_uid != expected_owner:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_invocation_owner_mismatch",
            f"The Codex hook {role} invocation owner changed; repair the installation.",
        )
    expected_link_target = identity.get("link_target")
    is_symlink = stat.S_ISLNK(metadata.st_mode)
    if expected_link_target is None:
        if is_symlink or not stat.S_ISREG(metadata.st_mode):
            raise CodexHookIntegrityError(
                f"codex_hook_{role}_invocation_type_mismatch",
                f"The Codex hook {role} invocation type changed; repair the installation.",
            )
    elif not isinstance(expected_link_target, str) or not is_symlink:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_invocation_type_mismatch",
            f"The Codex hook {role} invocation type changed; repair the installation.",
        )
    elif os.readlink(invocation) != expected_link_target:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_symlink_target_mismatch",
            f"The Codex hook {role} symlink target changed; repair the installation.",
        )
    if not os.access(invocation, os.X_OK):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_not_executable",
            f"The Codex hook {role} is not executable; repair the installation.",
        )
    target = identity.get("target")
    verify_regular_file_identity(target)
    if not isinstance(target, dict) or target.get("path") != canonical_path(invocation):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_target_path_mismatch",
            f"The Codex hook {role} target changed; repair the installation.",
        )


def validate_regular_file(path: Path, *, role: str, executable_required: bool) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_missing",
            f"The Codex hook {role} is missing; repair the installation.",
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_not_regular",
            f"The Codex hook {role} must be a regular file, not a symlink; repair the installation.",
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if os.name != "nt":
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and metadata.st_uid not in {current_uid, 0}:
            raise CodexHookIntegrityError(
                f"codex_hook_{role}_owner_untrusted",
                f"The Codex hook {role} has an unexpected owner; repair the installation.",
            )
        trusted_interpreter_group_write = role == "interpreter" and (
            (current_uid is not None and metadata.st_uid == current_uid)
            # Members of gid 0 already have the privilege needed to replace a
            # root-owned interpreter regardless of its group-write bit.  The
            # GitHub-hosted Python toolcache uses this conventional 0775,
            # root:root layout.
            or (metadata.st_uid == 0 and metadata.st_gid == 0)
        )
        unsafe_group_write = bool(mode & stat.S_IWGRP) and not trusted_interpreter_group_write
        if mode & stat.S_IWOTH or unsafe_group_write:
            raise CodexHookIntegrityError(
                f"codex_hook_{role}_permissions_unsafe",
                f"The Codex hook {role} is writable by another user; repair the installation.",
            )
        if executable_required and not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise CodexHookIntegrityError(
                f"codex_hook_{role}_not_executable",
                f"The Codex hook {role} is not executable; repair the installation.",
            )
    elif executable_required and not os.access(path, os.X_OK):
        raise CodexHookIntegrityError(
            f"codex_hook_{role}_not_executable",
            f"The Codex hook {role} is not executable; repair the installation.",
        )
    return metadata


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "CodexHookIntegrityError",
    "canonical_path",
    "describe_executable_file",
    "describe_regular_file",
    "split_hook_command",
    "validate_regular_file",
    "verify_executable_file_identity",
    "verify_regular_file_identity",
]
