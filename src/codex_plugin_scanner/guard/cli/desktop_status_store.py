"""An existing SQLite snapshot for passive Desktop observation, without repairs."""

from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from ..private_file_io import read_private_regular_text
from ..store import GuardStore
from ..store_base import _OAUTH_LOCAL_CREDENTIALS_HASH_KEY, _OAUTH_LOCAL_CREDENTIALS_REF_KEY, _normalize_source_name


class DesktopStatusStore(GuardStore):
    """Reuse Core readers with one read-only transaction and no store initialization.

    The normal GuardStore constructor migrates, repairs permissions, and may
    recover a damaged database. Passive Desktop polling must leave that work to
    startup or an explicit recovery action. SQLite rejects accidental writes
    from any inherited reader, including future changes to those readers.
    """

    def __init__(  # pyright: ignore[reportMissingSuperCall]
        self, guard_home: Path, *, source: str = "default"
    ) -> None:
        # Passive status deliberately bypasses the mutating GuardStore constructor.
        self.guard_home = guard_home
        self.path = guard_home / "guard.db"
        self._guard_source = _normalize_source_name(source)
        suffix = "" if self._guard_source == "default" else f":{self._guard_source}"
        self._oauth_local_credentials_state_key = f"oauth_local_credentials{suffix}"
        if self.path.is_symlink():
            raise ValueError("Guard status requires a regular local store")
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

    def get_cloud_workspace_id(self) -> str | None:
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        value = payload.get("workspace_id") if isinstance(payload, dict) else None
        return value.strip() if isinstance(value, str) and value.strip() else None

    def get_oauth_local_credential_health(self) -> dict[str, object]:
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        if not isinstance(payload, dict):
            return {"configured": False, "state": "not_configured"}
        metadata = self._oauth_local_credentials_metadata(payload)
        secret = _read_existing_oauth_secret(self.guard_home, payload)
        healthy = (
            metadata is not None
            and secret is not None
            and self._build_oauth_local_credentials_result(metadata=metadata, secret_payload=secret) is not None
        )
        return {"configured": True, "state": "healthy" if healthy else "degraded"}

    def get_cloud_sync_profile(self) -> dict[str, str] | None:
        from ..store_base import _oauth_sync_url_from_issuer

        if self.get_oauth_local_credential_health()["state"] != "healthy":
            return None
        payload = self.get_sync_payload(self._oauth_local_credentials_state_key)
        metadata = self._oauth_local_credentials_metadata(payload) if isinstance(payload, dict) else None
        if metadata is None:
            return None
        profile = {"auth_mode": "oauth", "sync_url": _oauth_sync_url_from_issuer(str(metadata["issuer"]))}
        workspace = self.get_cloud_workspace_id()
        if workspace is not None:
            profile["workspace_id"] = workspace
        return profile

    def receipt_summary_between(self, *, start_at: str, before_at: str) -> dict[str, object]:
        # Reuse clean rollups, then project only missing/dirty rows using the
        # same canonical decision helper as the ordinary rollup writer.
        from ..store_receipt_rollups import _canonical_action_from_row, _receipt_action_query

        clean = self._connection.execute(
            """select count(*) as total,
                      coalesce(sum(s.policy_decision = 'block'), 0) as blocked,
                      coalesce(sum(s.policy_decision in ('allow', 'warn')), 0) as approved
               from runtime_receipts r join receipt_rollup_actions s on s.receipt_id = r.receipt_id
               where r.timestamp >= ? and r.timestamp < ? and s.dirty = 0""",
            (start_at, before_at),
        ).fetchone()
        total, blocked, approved = int(clean["total"]), int(clean["blocked"]), int(clean["approved"])
        rows = self._connection.execute(
            _receipt_action_query(
                "left join receipt_rollup_actions s on s.receipt_id = r.receipt_id "
                "where r.timestamp >= ? and r.timestamp < ? and (s.receipt_id is null or s.dirty = 1)",
            ),
            (start_at, before_at),
        )
        for row in rows:
            action = _canonical_action_from_row(row)
            total += 1
            blocked += int(action == "block")
            approved += int(action in {"allow", "warn"})
        latest = self._connection.execute("select max(timestamp) from runtime_receipts").fetchone()
        return {
            "total": total,
            "blocked": blocked,
            "approved": approved,
            "latest_at": latest[0] if latest is not None else None,
        }


def _read_existing_oauth_secret(guard_home: Path, metadata: dict[str, object]) -> dict[str, object] | None:
    """Validate the existing local vault without creation, promotion, or Keychain UI."""
    from ..store_base import _secret_matches_hash

    secret_ref = metadata.get(_OAUTH_LOCAL_CREDENTIALS_REF_KEY)
    secret_hash = metadata.get(_OAUTH_LOCAL_CREDENTIALS_HASH_KEY)
    if (
        not isinstance(secret_ref, str)
        or not 0 < len(secret_ref) <= 512
        or "\\" in secret_ref
        or not isinstance(secret_hash, str)
    ):
        return None
    normalized_ref = secret_ref.replace("/", "_").replace(":", "_")
    key = read_private_regular_text(guard_home / "secrets" / "key.bin", max_bytes=4096, require_private_parent=True)
    encrypted = read_private_regular_text(
        guard_home / "secrets" / f"{normalized_ref}.enc",
        max_bytes=131072,
        require_private_parent=True,
    )
    if key is None or encrypted is None:
        return None
    try:
        envelope = json.loads(encrypted)
        if not isinstance(envelope, dict) or envelope.get("version") != "fernet-v1":
            return None
        token = envelope.get("ciphertext")
        if not isinstance(token, str):
            return None
        key_bytes = key.strip().encode("ascii")
        if len(key_bytes) == 32:
            key_bytes = base64.urlsafe_b64encode(key_bytes)
        secret_text = Fernet(key_bytes).decrypt(token.encode("ascii")).decode("utf-8")
        if not _secret_matches_hash(secret_text, secret_hash):
            return None
        secret = json.loads(secret_text)
        return secret if isinstance(secret, dict) else None
    except (InvalidToken, ValueError, TypeError, UnicodeError):
        return None
