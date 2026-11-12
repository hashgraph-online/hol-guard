"""Remove the separate Cloud actions sign-ins saved by alpha builds.

Alpha builds had `hol-guard cloud-actions login`, which saved a sign-in per
profile: a file under `<guard home>/cloud-actions/profiles/` naming a secret in
Guard's encrypted secret store, plus `clients.json` and `last-check.json`.
Cloud actions now use the `hol-guard connect` pairing, so those records are
unused. This deletes them, and the secrets they name, the first time a Cloud
actions command or the dashboard looks. AI tool settings backups under
`<guard home>/cloud-actions/settings-backups/` are kept.
"""

from __future__ import annotations

import json
import re
import shutil
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..store_base import EncryptedFileSecretStore

ALPHA_SIGN_IN_REMOVED_NOTICE = (
    "Removed the separate Cloud actions sign-in saved by an earlier version; "
    "Cloud actions now use this computer's `hol-guard connect` connection."
)
# Only secrets an alpha sign-in created; anything else in the secret store is left alone.
_SECRET_REF_PATTERN = re.compile(r"cloud-actions-[a-z0-9-]{1,32}-[0-9a-f]{16}")
_MAX_PROFILE_BYTES = 64 * 1024
# Profiles handled per run; any beyond this wait for the next command.
_MAX_PROFILES = 64


def _secret_ref(entry: Path) -> str | None:
    """The alpha secret this profile names, or None when it names none."""

    try:
        if entry.stat().st_size > _MAX_PROFILE_BYTES:
            return None
        payload = json.loads(entry.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ref = payload.get("secret_ref") if isinstance(payload, dict) else None
    return ref if isinstance(ref, str) and _SECRET_REF_PATTERN.fullmatch(ref) else None


def _remove_profiles(guard_home: Path, profiles: Path) -> None:
    """Delete each profile once its secret is gone; a failed one stays for the next run."""

    if profiles.is_symlink():
        with suppress(OSError):
            profiles.unlink()
        return
    try:
        entries = sorted(profiles.iterdir())[:_MAX_PROFILES]
    except OSError:
        return
    secrets: EncryptedFileSecretStore | None = None
    for entry in entries:
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
            continue
        ref = _secret_ref(entry) if entry.suffix == ".json" and not entry.is_symlink() else None
        if ref is not None:
            if secrets is None:
                from ..store_base import EncryptedFileSecretStore

                secrets = EncryptedFileSecretStore(guard_home)
            try:
                secrets.delete_secret(ref)
            except (OSError, RuntimeError):
                continue
        with suppress(OSError):
            entry.unlink()
    with suppress(OSError):
        profiles.rmdir()


def remove_alpha_sign_ins(guard_home: Path) -> bool:
    """Delete alpha sign-in records and their secrets; True when there were any."""

    root = guard_home / "cloud-actions"
    profiles = root / "profiles"
    leftovers = [root / "clients.json", root / "last-check.json"]
    has_profiles = profiles.is_symlink() or profiles.is_dir()
    if not has_profiles and not any(path.is_file() for path in leftovers):
        return False
    if has_profiles:
        _remove_profiles(guard_home, profiles)
    for path in leftovers:
        with suppress(FileNotFoundError, IsADirectoryError, PermissionError):
            path.unlink()
    return True


__all__ = ["ALPHA_SIGN_IN_REMOVED_NOTICE", "remove_alpha_sign_ins"]
