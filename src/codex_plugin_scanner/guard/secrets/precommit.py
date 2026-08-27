"""Non-destructive Git pre-commit integration for HOL Guard Secrets."""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .secret_repository_scanner import _run_git

_MANAGED_MARKER = "# HOL_GUARD_SECRETS_PRE_COMMIT_V1"
_BACKUP_NAME = "pre-commit.hol-guard-user"

_MANAGED_HOOK = f"""#!/bin/sh
{_MANAGED_MARKER}
# Managed by `hol-guard secrets install-hook`. Do not place secrets in this file.
hook_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
legacy="$hook_dir/{_BACKUP_NAME}"
if [ -x "$legacy" ]; then
  "$legacy" "$@"
  status=$?
  if [ "$status" -ne 0 ]; then
    exit "$status"
  fi
fi
exec hol-guard secrets scan --staged --fail-on-findings
"""


@dataclass(frozen=True, slots=True)
class SecretsHookResult:
    status: str
    hook: str
    chained_existing: bool

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": "guard-secrets-hook.v1",
            "status": self.status,
            "hook": self.hook,
            "chained_existing": self.chained_existing,
        }


def _git_common_dir(root: Path) -> Path:
    resolved = root.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("hook target must be an existing Git worktree directory")
    try:
        custom_hooks = _run_git(resolved, ["config", "--get", "core.hooksPath"])
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("hook target is not a usable Git worktree") from error
    if custom_hooks.returncode == 0 and custom_hooks.stdout.strip():
        raise ValueError(
            "custom core.hooksPath is configured; HOL Guard will not modify a shared or "
            "custom hook directory automatically"
        )
    try:
        result = _run_git(resolved, ["rev-parse", "--git-common-dir"])
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("hook target is not a usable Git worktree") from error
    if result.returncode != 0:
        raise ValueError("hook target is not a usable Git worktree")
    raw = result.stdout.decode("utf-8", errors="strict").strip()
    if not raw:
        raise ValueError("Git hook directory could not be resolved")
    path = Path(raw)
    return (path if path.is_absolute() else resolved / path).resolve()


def _open_hooks_directory(root: Path, *, create: bool) -> int | None:
    hooks_dir = _git_common_dir(root) / "hooks"
    if create:
        try:
            hooks_dir.mkdir(mode=0o700, exist_ok=True)
        except OSError as error:
            raise ValueError("Git hook directory could not be created safely") from error
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(hooks_dir, flags)
    except FileNotFoundError:
        if not create:
            return None
        raise ValueError("Git hook directory must be a real trusted directory") from None
    except OSError as error:
        raise ValueError("Git hook directory must be a real trusted directory") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("Git hook directory must be a real trusted directory")
    return descriptor


def _entry_stat(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _is_managed_hook(directory: int, name: str) -> bool:
    entry = _entry_stat(directory, name)
    if entry is None or not stat.S_ISREG(entry.st_mode):
        return False
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        with os.fdopen(descriptor, encoding="utf-8", errors="replace") as handle:
            prefix = handle.read(512)
    except OSError:
        return False
    return _MANAGED_MARKER in prefix


def _require_regular_entry(directory: int, name: str) -> None:
    entry = _entry_stat(directory, name)
    if entry is not None and not stat.S_ISREG(entry.st_mode):
        raise ValueError("refusing to modify a non-regular Git hook entry")


def install_precommit_hook(root: Path) -> SecretsHookResult:
    """Install the managed hook while preserving any existing user hook."""

    directory = _open_hooks_directory(root, create=True)
    if directory is None:  # pragma: no cover - create=True guarantees a directory or raises
        raise ValueError("Git hook directory could not be created safely")
    hook = "pre-commit"
    backup = _BACKUP_NAME
    display = "git-hooks/pre-commit"
    temp = f".{hook}.hol-guard-{os.getpid()}.tmp"
    moved_existing = False
    try:
        _require_regular_entry(directory, hook)
        _require_regular_entry(directory, backup)
        if _is_managed_hook(directory, hook):
            return SecretsHookResult(
                status="already_installed",
                hook=display,
                chained_existing=_entry_stat(directory, backup) is not None,
            )
        hook_exists = _entry_stat(directory, hook) is not None
        if hook_exists and _entry_stat(directory, backup) is not None:
            raise ValueError("refusing to replace pre-commit hook because the HOL Guard backup path already exists")

        if hook_exists:
            os.replace(hook, backup, src_dir_fd=directory, dst_dir_fd=directory)
            moved_existing = True
        descriptor = os.open(
            temp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o755,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(_MANAGED_HOOK)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, hook, src_dir_fd=directory, dst_dir_fd=directory)
    except OSError as error:
        try:
            if _entry_stat(directory, temp) is not None:
                os.unlink(temp, dir_fd=directory)
            if moved_existing and _entry_stat(directory, backup) is not None and _entry_stat(directory, hook) is None:
                os.replace(backup, hook, src_dir_fd=directory, dst_dir_fd=directory)
        except OSError:
            pass
        raise ValueError("could not install HOL Guard Secrets pre-commit hook") from error
    finally:
        os.close(directory)

    return SecretsHookResult(status="installed", hook=display, chained_existing=moved_existing)


def uninstall_precommit_hook(root: Path) -> SecretsHookResult:
    """Remove only the managed hook and restore a chained user hook exactly."""

    directory = _open_hooks_directory(root, create=False)
    hook = "pre-commit"
    backup = _BACKUP_NAME
    display = "git-hooks/pre-commit"
    if directory is None:
        return SecretsHookResult(status="not_installed", hook=display, chained_existing=False)
    try:
        _require_regular_entry(directory, hook)
        _require_regular_entry(directory, backup)
        if _entry_stat(directory, hook) is None:
            if _entry_stat(directory, backup) is not None:
                try:
                    os.replace(backup, hook, src_dir_fd=directory, dst_dir_fd=directory)
                except OSError as error:
                    raise ValueError("could not restore the preserved pre-commit hook") from error
                return SecretsHookResult(status="restored", hook=display, chained_existing=True)
            return SecretsHookResult(status="not_installed", hook=display, chained_existing=False)
        if not _is_managed_hook(directory, hook):
            if _entry_stat(directory, backup) is not None:
                raise ValueError(
                    "refusing to overwrite a non-HOL-Guard pre-commit hook while a preserved backup exists"
                )
            return SecretsHookResult(status="not_installed", hook=display, chained_existing=False)

        try:
            os.unlink(hook, dir_fd=directory)
            restored = _entry_stat(directory, backup) is not None
            if restored:
                os.replace(backup, hook, src_dir_fd=directory, dst_dir_fd=directory)
        except OSError as error:
            raise ValueError("could not uninstall HOL Guard Secrets pre-commit hook") from error
        return SecretsHookResult(
            status="restored" if restored else "uninstalled",
            hook=display,
            chained_existing=restored,
        )
    finally:
        os.close(directory)


__all__ = [
    "SecretsHookResult",
    "install_precommit_hook",
    "uninstall_precommit_hook",
]
