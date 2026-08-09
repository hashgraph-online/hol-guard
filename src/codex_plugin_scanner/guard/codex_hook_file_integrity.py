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
import sys
import sysconfig
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


def _owner_is_only_group_member(owner_uid: int, group_gid: int) -> bool:
    """Return whether a POSIX group is provably private to one file owner.

    Linux distributions commonly create one primary group per user and pair it
    with a 0002 umask.  That can produce user-owned 0664 config files and
    package modules extracted by pip/pipx.  The group write bit is safe only
    when NSS can prove that no other account belongs to that group.  Lookup
    failures remain fail-closed.

    User-private groups often have an empty ``gr_mem`` list (membership is only
    via ``pw_gid``).  Some restricted NSS configurations also return an empty
    ``getpwall()`` result.  In that case the classic ``group name == username``
    user-private-group convention plus matching primary gid is accepted; any
    evidence of a second member still rejects.
    """

    try:
        import grp
        import pwd

        owner = pwd.getpwuid(owner_uid)
        group = grp.getgrgid(group_gid)
        owner_in_group = owner.pw_gid == group_gid or owner.pw_name in set(group.gr_mem)
        if not owner_in_group:
            return False
        accounts = pwd.getpwall()
        member_names = set(group.gr_mem)
        member_names.update(entry.pw_name for entry in accounts if entry.pw_gid == group_gid)
        other_members = member_names - {owner.pw_name}
        if other_members:
            return False
        # Proven private membership: the owner is listed and no one else is.
        if owner.pw_name in member_names:
            return True
        # Empty NSS listing cannot prove absence of other primary members. Accept
        # only the classic user-private-group convention (group name == username,
        # matching primary gid, empty gr_mem). Partial non-empty listings fail closed.
        return not accounts and not group.gr_mem and group.gr_name == owner.pw_name and owner.pw_gid == group_gid
    except (ImportError, KeyError, OSError):
        return False


def _python_package_roots() -> tuple[Path, ...]:
    """Return package roots belonging to the running Python installation.

    ``sysconfig`` supplies the authoritative purelib/platlib locations for the
    active interpreter.  The explicit prefix-derived candidates cover common
    POSIX venv and distro layouts, including Debian/Ubuntu ``dist-packages``,
    without trusting an arbitrary directory merely because it has a familiar
    basename.  ``site`` and the installed ``codex_plugin_scanner`` location cover
    pipx/venv layouts where the active purelib spelling differs from the path
    that imported the package.
    """

    roots: set[Path] = set()

    def add_root(value: str | Path | None) -> None:
        if value is None:
            return
        try:
            roots.add(Path(value).expanduser().resolve(strict=False))
        except (OSError, RuntimeError):
            return

    try:
        configured_paths = sysconfig.get_paths()
    except (AttributeError, OSError, ValueError):
        configured_paths = {}
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if isinstance(value, str) and value:
            add_root(value)

    try:
        import site

        getsitepackages = getattr(site, "getsitepackages", None)
        if callable(getsitepackages):
            site_packages = getsitepackages()
            if isinstance(site_packages, (list, tuple)):
                for value in site_packages:
                    if isinstance(value, str) and value:
                        add_root(value)
        getusersitepackages = getattr(site, "getusersitepackages", None)
        if callable(getusersitepackages):
            user_site = getusersitepackages()
            if isinstance(user_site, str) and user_site:
                add_root(user_site)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        pass

    try:
        import codex_plugin_scanner

        package_file = getattr(codex_plugin_scanner, "__file__", None)
        if isinstance(package_file, str) and package_file:
            # site-packages/codex_plugin_scanner/__init__.py -> site-packages
            add_root(Path(package_file).expanduser().resolve(strict=False).parent.parent)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        pass

    version_dirs = {
        f"python{sys.version_info.major}",
        f"python{sys.version_info.major}.{sys.version_info.minor}",
    }
    for prefix_value in {sys.prefix, sys.exec_prefix}:
        if not prefix_value:
            continue
        try:
            prefix = Path(prefix_value).expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        for lib_dir in ("lib", "lib64"):
            for version_dir in version_dirs:
                for package_dir in ("site-packages", "dist-packages"):
                    add_root(prefix / lib_dir / version_dir / package_dir)

    return tuple(sorted(roots, key=str))


def _is_installed_python_package_file(path: Path) -> bool:
    """Return whether a file is under a package root for this interpreter."""

    try:
        canonical = path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    for root in _python_package_roots():
        try:
            relative = canonical.relative_to(root)
        except ValueError:
            continue
        if relative.parts:
            return True
    return False


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
        trusted_user_private_group_write = (
            current_uid is not None
            and metadata.st_uid == current_uid
            and (role == "config_target" or _is_installed_python_package_file(path))
            and _owner_is_only_group_member(current_uid, metadata.st_gid)
        )
        unsafe_group_write = bool(mode & stat.S_IWGRP) and not (
            trusted_interpreter_group_write or trusted_user_private_group_write
        )
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
