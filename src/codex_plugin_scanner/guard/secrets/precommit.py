"""Non-destructive Git pre-commit integration for HOL Guard Secrets."""

from __future__ import annotations

import os
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


def _hook_paths(root: Path) -> tuple[Path, Path, str]:
    hooks_dir = _git_common_dir(root) / "hooks"
    return hooks_dir / "pre-commit", hooks_dir / _BACKUP_NAME, "git-hooks/pre-commit"


def _is_managed_hook(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        prefix = path.read_text(encoding="utf-8", errors="replace")[:512]
    except OSError:
        return False
    return _MANAGED_MARKER in prefix


def install_precommit_hook(root: Path) -> SecretsHookResult:
    """Install the managed hook while preserving any existing user hook."""

    hook, backup, display = _hook_paths(root)
    hook.parent.mkdir(parents=True, exist_ok=True)
    if _is_managed_hook(hook):
        return SecretsHookResult(
            status="already_installed",
            hook=display,
            chained_existing=backup.exists(),
        )
    if hook.exists() and backup.exists():
        raise ValueError("refusing to replace pre-commit hook because the HOL Guard backup path already exists")

    moved_existing = False
    temp = hook.with_name(f".{hook.name}.hol-guard-{os.getpid()}.tmp")
    try:
        if hook.exists():
            os.replace(hook, backup)
            moved_existing = True
        temp.write_text(_MANAGED_HOOK, encoding="utf-8", newline="\n")
        temp.chmod(0o755)
        os.replace(temp, hook)
    except OSError as error:
        try:
            if temp.exists():
                temp.unlink()
            if moved_existing and backup.exists() and not hook.exists():
                os.replace(backup, hook)
        except OSError:
            pass
        raise ValueError("could not install HOL Guard Secrets pre-commit hook") from error

    return SecretsHookResult(
        status="installed",
        hook=display,
        chained_existing=backup.exists(),
    )


def uninstall_precommit_hook(root: Path) -> SecretsHookResult:
    """Remove only the managed hook and restore a chained user hook exactly."""

    hook, backup, display = _hook_paths(root)
    if not hook.exists():
        if backup.exists():
            try:
                os.replace(backup, hook)
            except OSError as error:
                raise ValueError("could not restore the preserved pre-commit hook") from error
            return SecretsHookResult(status="restored", hook=display, chained_existing=True)
        return SecretsHookResult(status="not_installed", hook=display, chained_existing=False)
    if not _is_managed_hook(hook):
        if backup.exists():
            raise ValueError("refusing to overwrite a non-HOL-Guard pre-commit hook while a preserved backup exists")
        return SecretsHookResult(status="not_installed", hook=display, chained_existing=False)

    try:
        hook.unlink()
        restored = backup.exists()
        if restored:
            os.replace(backup, hook)
    except OSError as error:
        raise ValueError("could not uninstall HOL Guard Secrets pre-commit hook") from error
    return SecretsHookResult(
        status="restored" if restored else "uninstalled",
        hook=display,
        chained_existing=restored,
    )


__all__ = [
    "SecretsHookResult",
    "install_precommit_hook",
    "uninstall_precommit_hook",
]
