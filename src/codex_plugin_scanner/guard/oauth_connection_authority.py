"""Local connection authority captured independently of removable credentials."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from typing import Literal, cast

_CREDENTIAL_KEY = "oauth_local_credentials"
_EPOCH_PREFIX = "oauth_connection_epoch:"
CONNECTION_AUTHORITY_VERSION_KEY = "_connection_authority_version"
_BINDING_FIELDS = (
    "issuer",
    "client_id",
    "grant_id",
    "device_id",
    "machine_id",
    "workspace_id",
    "runtime_id",
    "dpop_private_key_pem",
    "dpop_public_jwk",
    "dpop_public_jwk_thumbprint",
)


def is_oauth_credential_key(state_key: str) -> bool:
    return state_key == _CREDENTIAL_KEY or state_key.startswith(_CREDENTIAL_KEY + ":")


def connection_epoch_key(credential_key: str) -> str:
    if not is_oauth_credential_key(credential_key):
        raise ValueError("Invalid credential state key.")
    return _EPOCH_PREFIX + credential_key


@dataclass(frozen=True, slots=True)
class ConnectionAuthority:
    state: Literal["missing", "invalid", "ready", "pending"]
    epoch: str | None = None
    reset_token: str | None = None


def _valid_nonce(value: object) -> bool:
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate authority field.")
        result[key] = value
    return result


def read_connection_authority(connection: sqlite3.Connection, credential_key: str) -> ConnectionAuthority:
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?", (connection_epoch_key(credential_key),)
    ).fetchone()
    if row is None:
        return ConnectionAuthority("missing")
    try:
        payload = json.loads(str(row[0]), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return ConnectionAuthority("invalid")
    if not isinstance(payload, dict) or set(payload) not in ({"epoch"}, {"epoch", "reset"}):
        return ConnectionAuthority("invalid")
    epoch = payload.get("epoch")
    if not _valid_nonce(epoch):
        return ConnectionAuthority("invalid")
    if "reset" in payload:
        reset_token = payload["reset"]
        if not _valid_nonce(reset_token):
            return ConnectionAuthority("invalid")
        return ConnectionAuthority("pending", cast(str, epoch), cast(str, reset_token))
    return ConnectionAuthority("ready", cast(str, epoch))


def read_connection_epoch(connection: sqlite3.Connection, credential_key: str) -> str | None:
    return read_connection_authority(connection, credential_key).epoch


def _read_credential_payload(connection: sqlite3.Connection, credential_key: str) -> dict[str, object] | None:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (credential_key,)).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(str(row[0]))
    except (TypeError, ValueError):
        return None
    return cast(dict[str, object], payload) if isinstance(payload, dict) else None


def capture_connection_epoch(connection: sqlite3.Connection, credential_key: str, now: str) -> str | None:
    authority = read_connection_authority(connection, credential_key)
    if authority.state not in {"missing", "ready"}:
        return None
    payload = _read_credential_payload(connection, credential_key)
    if payload is None:
        return None
    adopted = CONNECTION_AUTHORITY_VERSION_KEY in payload
    if adopted and (
        type(payload[CONNECTION_AUTHORITY_VERSION_KEY]) is not int or payload[CONNECTION_AUTHORITY_VERSION_KEY] != 1
    ):
        return None
    if authority.state == "missing":
        if adopted:
            # Loss of previously adopted authority is not a legacy connection.
            return None
        epoch = advance_connection_epoch(connection, credential_key, now)
    else:
        epoch = authority.epoch
    if not adopted:
        payload[CONNECTION_AUTHORITY_VERSION_KEY] = 1
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?", (json.dumps(payload), credential_key)
        )
    return epoch


def advance_connection_epoch(
    connection: sqlite3.Connection,
    credential_key: str,
    now: str,
    *,
    reset_token: str | None = None,
    complete_reset_token: str | None = None,
) -> str:
    epoch = uuid.uuid4().hex
    prior = read_connection_authority(connection, credential_key)
    payload: dict[str, object] = {"epoch": epoch}
    if complete_reset_token is not None:
        if prior.state != "pending" or prior.reset_token != complete_reset_token:
            raise RuntimeError("The connection reset changed before completion.")
    elif reset_token is not None:
        if not _valid_nonce(reset_token):
            raise ValueError("Invalid connection reset token.")
        payload["reset"] = reset_token
    elif prior.state == "pending":
        payload["reset"] = prior.reset_token
    else:
        credentials = _read_credential_payload(connection, credential_key)
        adopted = credentials is not None and CONNECTION_AUTHORITY_VERSION_KEY in credentials
        if prior.state == "invalid" or (prior.state == "missing" and adopted):
            # Ordinary replacement or repair cannot reopen uncertain reset state.
            # Only a complete serialized reset can establish ready authority again.
            payload["reset"] = uuid.uuid4().hex
    credentials = _read_credential_payload(connection, credential_key)
    if credentials is not None:
        credentials[CONNECTION_AUTHORITY_VERSION_KEY] = 1
        connection.execute(
            "update sync_state set payload_json = ? where state_key = ?", (json.dumps(credentials), credential_key)
        )
    connection.execute(
        """
        insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)
        on conflict(state_key) do update set payload_json = excluded.payload_json, updated_at = excluded.updated_at
        """,
        (connection_epoch_key(credential_key), json.dumps(payload), now),
    )
    return epoch


def connection_identity(credentials: dict[str, object]) -> str:
    return json.dumps({key: credentials.get(key) for key in _BINDING_FIELDS}, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class OAuthConnectAttempt:
    """One initial authorization, bound to a store/source before external work."""

    credential_key: str
    epoch: str
    store_scope: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class OAuthConnectionSnapshot:
    """Immutable private snapshot; credentials never appear in its representation."""

    credential_key: str
    epoch: str
    store_scope: str = field(repr=False)
    _credentials_json: str = field(repr=False)

    @classmethod
    def capture(
        cls, credential_key: str, epoch: str, store_scope: str, credentials: dict[str, object]
    ) -> OAuthConnectionSnapshot:
        return cls(credential_key, epoch, store_scope, json.dumps(credentials, sort_keys=True, separators=(",", ":")))

    def credentials(self) -> dict[str, object]:
        # Each consumer receives a copy, leaving the captured compare-and-set value immutable.
        return cast(dict[str, object], json.loads(self._credentials_json))

    def same_authority(self, other: OAuthConnectionSnapshot) -> bool:
        return (
            self.credential_key == other.credential_key
            and self.epoch == other.epoch
            and self.store_scope == other.store_scope
            and connection_identity(self.credentials()) == connection_identity(other.credentials())
        )
