"""Read one existing status snapshot without store, credential or identity repair."""

from __future__ import annotations

import base64
import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .private_file_io import read_private_regular_bytes, read_private_regular_text
from .store import GuardStore
from .store_base import (
    _DEVICE_ROW_KEY,
    _POLICY_INTEGRITY_CACHE_TTL_SECONDS,
    _POLICY_INTEGRITY_KEY_REF,
    EncryptedFileSecretStore,
    FallbackSecretStore,
    SystemKeyringSecretStore,
    _normalize_source_name,
    _oauth_sync_url_from_issuer,
    _secret_matches_hash,
)
from .store_secret_policy_integrity import _build_policy_integrity_secret_store_compat


class PassiveStatusStore(GuardStore):
    """Reuse status readers over an enforced read-only transaction.

    The existing store supplies its configured signer backend and already cached
    signer material. This adapter never creates a vault, promotes a credential,
    repairs metadata or creates a device identity. An OS-only signer retains its
    existing protected read path; fallback signers never promote a primary key.
    """

    def __init__(  # pyright: ignore[reportMissingSuperCall]
        self, store: GuardStore | Path, *, source: str = "default", allow_system_keyring: bool = False
    ) -> None:
        # Normal GuardStore initialization performs writes and is deliberately bypassed.
        self.guard_home = store if isinstance(store, Path) else store.guard_home
        self.path = self.guard_home / "guard.db"
        self._guard_source = _normalize_source_name(source if isinstance(store, Path) else store.guard_source)
        suffix = "" if self._guard_source == "default" else f":{self._guard_source}"
        self._oauth_local_credentials_state_key = f"oauth_local_credentials{suffix}"
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("Guard status requires an existing regular local store")
        if isinstance(store, Path):
            self._policy_integrity_key_ref = self._build_scoped_secret_ref(_POLICY_INTEGRITY_KEY_REF)
            self._cached_policy_integrity_secret_material = None
            backend = _build_policy_integrity_secret_store_compat(
                self.guard_home, allow_system_keyring=allow_system_keyring
            )
        else:
            self._policy_integrity_key_ref = store._policy_integrity_key_ref
            self._cached_policy_integrity_secret_material = store._cached_policy_integrity_secret_material
            backend = store._policy_integrity_secret_store
        self._system_signer = backend if isinstance(backend, SystemKeyringSecretStore) else None
        fallback = backend.fallback if isinstance(backend, FallbackSecretStore) else backend
        self._local_signer_allowed = (
            isinstance(fallback, EncryptedFileSecretStore) and fallback.base_dir == self.guard_home / "secrets"
        )
        self._connection = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True, timeout=1.0)
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("pragma query_only=on")
            self._connection.execute("begin")
        except sqlite3.DatabaseError:
            self._connection.close()
            raise

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        yield self._connection

    def close(self) -> None:
        self._connection.close()

    def get_or_create_installation_id(self) -> str:
        row = self._connection.execute(
            "select installation_id from guard_devices where device_key = ?", (_DEVICE_ROW_KEY,)
        ).fetchone()
        return str(row["installation_id"]) if row is not None and row["installation_id"] else ""

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object] | None:
        del allow_primary
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        if not isinstance(payload, dict):
            return None
        metadata = self._oauth_local_credentials_metadata(payload)
        text = read_existing_vault_text(self.guard_home, payload.get("credentials_ref"))
        fingerprint = payload.get("credentials_sha256")
        if (
            metadata is None
            or text is None
            or not isinstance(fingerprint, str)
            or not _secret_matches_hash(text, fingerprint)
        ):
            return None
        try:
            secret = json.loads(text)
        except ValueError:
            return None
        return (
            self._build_oauth_local_credentials_result(metadata=metadata, secret_payload=secret)
            if isinstance(secret, dict)
            else None
        )

    def get_oauth_local_credential_health(self) -> dict[str, object]:
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        if not isinstance(payload, dict):
            return {"configured": False, "state": "not_configured"}
        return {
            "configured": True,
            "state": "healthy" if self.get_oauth_local_credentials() is not None else "degraded",
        }

    def get_cloud_sync_profile(self) -> dict[str, str] | None:
        credentials = self.get_oauth_local_credentials()
        if credentials is None:
            return None
        profile = {"auth_mode": "oauth", "sync_url": _oauth_sync_url_from_issuer(str(credentials["issuer"]))}
        workspace = credentials.get("workspace_id")
        if isinstance(workspace, str) and workspace.strip():
            profile["workspace_id"] = workspace.strip()
        return profile

    def _policy_integrity_secret_material(
        self, *, create: bool, connection: sqlite3.Connection | None = None
    ) -> tuple[bytes | None, str | None]:
        if create:
            raise RuntimeError("Passive status cannot create an integrity key")
        if connection is not None and connection is not self._connection:
            raise RuntimeError("Passive status requires its existing snapshot connection")
        cached = self._cached_policy_integrity_secret_material
        if (
            cached is not None
            and cached[0] == self._policy_integrity_cache_marker()
            and 0 <= time.monotonic() - cached[1] < _POLICY_INTEGRITY_CACHE_TTL_SECONDS
        ):
            return cached[2]
        encoded = None
        if self._local_signer_allowed:
            encoded = read_existing_vault_text(self.guard_home, self._policy_integrity_key_ref)
        elif self._system_signer is not None:
            try:
                encoded = self._system_signer.get_secret_with_timeout(
                    self._policy_integrity_key_ref, timeout_seconds=0.5
                )
            except (OSError, RuntimeError, ValueError):
                return None, None
        if encoded is None:
            return None, None
        try:
            material = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, UnicodeError):
            return None, None
        if len(material) != 32:
            return None, None
        return material, self._versioned_secret_ref(self._policy_integrity_key_ref, sha256(material).hexdigest())


def read_existing_vault_text(guard_home: Path, secret_ref: object) -> str | None:
    """Read an existing private Fernet envelope without migration or key creation."""
    if not isinstance(secret_ref, str) or not 0 < len(secret_ref) <= 512 or "\\" in secret_ref:
        return None
    normalized = secret_ref.replace("/", "_").replace(":", "_")
    key = read_private_regular_bytes(guard_home / "secrets" / "key.bin", max_bytes=4096, require_private_parent=True)
    envelope_text = read_private_regular_text(
        guard_home / "secrets" / f"{normalized}.enc", max_bytes=131072, require_private_parent=True
    )
    if key is None or envelope_text is None:
        return None
    try:
        envelope = json.loads(envelope_text)
        if not isinstance(envelope, dict) or envelope.get("version") != "fernet-v1":
            return None
        ciphertext = envelope.get("ciphertext")
        if not isinstance(ciphertext, str):
            return None
        key = key.strip()
        return Fernet(key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, UnicodeError):
        return None
