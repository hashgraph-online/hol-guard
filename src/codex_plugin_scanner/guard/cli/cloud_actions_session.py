"""Saved Cloud actions sign-ins, one per profile.

A profile names one sign-in: one Guard Cloud, one workspace, one grant. The
details that are safe to show (Guard Cloud, workspace, scopes, expiry) live in
`<guard home>/cloud-actions/profiles/<profile>.json`. The access and refresh
credentials live in Guard's encrypted secret store, never in that file and
never in the device sign-in written by `hol-guard connect`.

Each sign-in gets its own secret ID, named in the profile file. Writing the
profile file is the commit: a save that fails before it leaves the previous
profile and its credentials untouched, and a lock keeps two sign-ins for the
same profile from interleaving.
"""

from __future__ import annotations

import json
import os
import re
import secrets as _secrets
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..daemon.atomic_replace import replace_file
from ..mdm.file_lock import acquire_file_lock, release_file_lock
from ..store_base import EncryptedFileSecretStore, SecretStore

DEFAULT_PROFILE = "default"
PROFILE_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_SCHEMA = "guard.cloud-actions.profile.v1"
_MAX_FILE_BYTES = 64 * 1024
_LOCK_WAIT_SECONDS = 10.0
_SECRET_REF_PATTERN = re.compile(r"cloud-actions-[a-z0-9-]{1,32}-[0-9a-f]{16}")


class CloudActionsProfileBusyError(RuntimeError):
    """Another Guard process is changing the same profile."""


@dataclass(frozen=True)
class CloudActionsProfile:
    name: str
    issuer: str
    resource: str
    client_id: str
    workspace_id: str
    scopes: tuple[str, ...]
    expires_at: str
    grant_id: str | None
    signed_in_at: str

    def is_expired(self, now: datetime | None = None) -> bool:
        try:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if expires.tzinfo is None:
            # Guard always saves an offset; a value without one is damaged.
            return True
        return expires <= (now or datetime.now(timezone.utc))


@dataclass(frozen=True)
class CloudActionsSecrets:
    access_token: str
    refresh_token: str | None


class CloudActionsSessionStore:
    def __init__(self, guard_home: Path, *, secret_store: SecretStore | None = None) -> None:
        self._root = guard_home / "cloud-actions"
        self._secrets = secret_store if secret_store is not None else EncryptedFileSecretStore(guard_home)

    @property
    def root(self) -> Path:
        return self._root

    def _profile_path(self, name: str) -> Path:
        if PROFILE_PATTERN.fullmatch(name) is None:
            raise ValueError("invalid profile name")
        return self._root / "profiles" / f"{name}.json"

    def _record(self, name: str) -> dict[str, object] | None:
        payload = _read_json(self._profile_path(name))
        if payload is None or payload.get("schema") != _SCHEMA:
            return None
        return payload

    def _secret_ref(self, name: str) -> str | None:
        payload = self._record(name)
        ref = payload.get("secret_ref") if payload is not None else None
        return ref if isinstance(ref, str) and _SECRET_REF_PATTERN.fullmatch(ref) else None

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        """Hold the profile's lock; raises CloudActionsProfileBusyError after a short wait."""

        path = self._profile_path(name)
        _ensure_private_dir(path.parent)
        with (path.parent / f".{name}.lock").open("a+b") as handle:
            if os.name != "nt":
                # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                os.chmod(handle.name, 0o600)
            deadline = time.monotonic() + _LOCK_WAIT_SECONDS
            while True:
                try:
                    acquire_file_lock(handle)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise CloudActionsProfileBusyError(name) from None
                    time.sleep(0.1)
            try:
                yield
            finally:
                release_file_lock(handle)

    def load(self, name: str) -> CloudActionsProfile | None:
        payload = self._record(name)
        if payload is None:
            return None
        try:
            scopes = payload["scopes"]
            if not isinstance(scopes, list):
                return None
            profile = CloudActionsProfile(
                name=name,
                issuer=str(payload["issuer"]),
                resource=str(payload["resource"]),
                client_id=str(payload["client_id"]),
                workspace_id=str(payload["workspace_id"]),
                scopes=tuple(str(scope) for scope in scopes),
                expires_at=str(payload["expires_at"]),
                grant_id=None if payload.get("grant_id") is None else str(payload["grant_id"]),
                signed_in_at=str(payload["signed_in_at"]),
            )
        except KeyError:
            return None
        return profile

    def load_secrets(self, name: str) -> CloudActionsSecrets | None:
        ref = self._secret_ref(name)
        raw = self._secrets.get_secret(ref) if ref is not None else None
        if raw is None:
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        access_token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(access_token, str) or not access_token:
            return None
        refresh_token = payload.get("refresh_token")
        return CloudActionsSecrets(
            access_token=access_token,
            refresh_token=refresh_token if isinstance(refresh_token, str) and refresh_token else None,
        )

    def save(self, profile: CloudActionsProfile, secrets: CloudActionsSecrets) -> str | None:
        """Save under a new secret ID; returns the replaced one for `discard_secret`.

        Call while holding `lock(profile.name)`. The profile file write is the
        commit; if anything fails before it, the new secret is removed and the
        previous sign-in stays as it was.
        """

        path = self._profile_path(profile.name)
        _ensure_private_dir(path.parent)
        previous_ref = self._secret_ref(profile.name)
        ref = f"cloud-actions-{profile.name}-{_secrets.token_hex(8)}"
        record = {"schema": _SCHEMA, **asdict(profile), "secret_ref": ref}
        record.pop("name")
        record["scopes"] = list(profile.scopes)
        self._secrets.set_secret(ref, json.dumps(asdict(secrets), sort_keys=True))
        try:
            _write_private_atomic(path, json.dumps(record, indent=2, sort_keys=True) + "\n")
        except BaseException:
            self._secrets.delete_secret(ref)
            raise
        return previous_ref

    def discard_secret(self, ref: str | None) -> None:
        if ref is not None and _SECRET_REF_PATTERN.fullmatch(ref):
            with suppress(OSError):
                self._secrets.delete_secret(ref)

    def delete(self, name: str) -> bool:
        """Remove the profile; call while holding `lock(name)`."""

        path = self._profile_path(name)
        ref = self._secret_ref(name)
        existed = path.exists()
        with suppress(FileNotFoundError):
            path.unlink()
        self.discard_secret(ref)
        return existed

    def registered_client(self, issuer: str) -> str | None:
        payload = _read_json(self._root / "clients.json")
        client_id = payload.get(issuer) if payload is not None else None
        return client_id if isinstance(client_id, str) and client_id else None

    def remember_client(self, issuer: str, client_id: str) -> None:
        path = self._root / "clients.json"
        _ensure_private_dir(self._root)
        payload = _read_json(path) or {}
        payload[issuer] = client_id
        _write_private_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > _MAX_FILE_BYTES:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        # Owner-only access: the folder names this person's Guard Cloud workspaces.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o700)


def _write_private_atomic(path: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        replace_file(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary_path.unlink()


__all__ = [
    "DEFAULT_PROFILE",
    "PROFILE_PATTERN",
    "CloudActionsProfile",
    "CloudActionsProfileBusyError",
    "CloudActionsSecrets",
    "CloudActionsSessionStore",
]
