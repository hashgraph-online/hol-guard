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

ALPHA_SIGN_IN_REMOVED_NOTICE = (
    "Removed the separate Cloud actions sign-in saved by an earlier version; "
    "Cloud actions now use this computer's `hol-guard connect` connection."
)
# Only secrets an alpha sign-in created; anything else in the secret store is left alone.
_SECRET_REF_PATTERN = re.compile(r"cloud-actions-[a-z0-9-]{1,32}-[0-9a-f]{16}")
_MAX_PROFILE_BYTES = 64 * 1024
_MAX_PROFILES = 64


def _secret_refs(profiles: Path) -> list[str]:
    refs: list[str] = []
    try:
        entries = sorted(profiles.iterdir())[:_MAX_PROFILES]
    except OSError:
        return refs
    for entry in entries:
        if entry.suffix != ".json" or not entry.is_file() or entry.is_symlink():
            continue
        try:
            if entry.stat().st_size > _MAX_PROFILE_BYTES:
                continue
            payload = json.loads(entry.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        ref = payload.get("secret_ref") if isinstance(payload, dict) else None
        if isinstance(ref, str) and _SECRET_REF_PATTERN.fullmatch(ref):
            refs.append(ref)
    return refs


def remove_alpha_sign_ins(guard_home: Path) -> bool:
    """Delete alpha sign-in records and their secrets; True when there were any."""

    root = guard_home / "cloud-actions"
    profiles = root / "profiles"
    leftovers = [root / "clients.json", root / "last-check.json"]
    if not profiles.is_dir() and not any(path.is_file() for path in leftovers):
        return False
    refs = _secret_refs(profiles) if profiles.is_dir() and not profiles.is_symlink() else []
    if refs:
        from ..store_base import EncryptedFileSecretStore

        secrets = EncryptedFileSecretStore(guard_home)
        for ref in refs:
            with suppress(OSError, RuntimeError):
                secrets.delete_secret(ref)
    if profiles.is_symlink():
        with suppress(OSError):
            profiles.unlink()
    elif profiles.is_dir():
        shutil.rmtree(profiles, ignore_errors=True)
    for path in leftovers:
        with suppress(FileNotFoundError, IsADirectoryError, PermissionError):
            path.unlink()
    return True


__all__ = ["ALPHA_SIGN_IN_REMOVED_NOTICE", "remove_alpha_sign_ins"]
