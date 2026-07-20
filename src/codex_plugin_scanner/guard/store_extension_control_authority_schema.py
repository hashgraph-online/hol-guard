"""Forward-only SQLite schema for extension-control authority records."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Final, cast

from .runtime.extension_control_authority import ExtensionControlAuthorityError

EXTENSION_CONTROL_SCHEMA_VERSION: Final = 1
_SCHEMA_CHECKSUM: Final = hashlib.sha256(b"hol-guard.extension-control-authority.schema.v1").hexdigest()


def ensure_extension_control_authority_schema(connection: sqlite3.Connection) -> None:
    _ = connection.execute(
        """
        create table if not exists extension_control_schema_migration (
            singleton integer primary key check (singleton = 1),
            version integer not null,
            checksum text not null
        )
        """
    )
    row = cast(
        object,
        connection.execute(
            "select version, checksum from extension_control_schema_migration where singleton = 1"
        ).fetchone(),
    )
    if row is None:
        _ = connection.execute(
            "insert into extension_control_schema_migration (singleton, version, checksum) values (1, ?, ?)",
            (EXTENSION_CONTROL_SCHEMA_VERSION, _SCHEMA_CHECKSUM),
        )
    else:
        if isinstance(row, sqlite3.Row):
            version_raw = cast(object, row["version"])
            checksum_raw = cast(object, row["checksum"])
        elif isinstance(row, tuple):
            row_values = cast(tuple[object, ...], row)
            if len(row_values) != 2:
                raise ExtensionControlAuthorityError("invalid extension control schema marker")
            version_raw, checksum_raw = row_values
        else:
            raise ExtensionControlAuthorityError("invalid extension control schema marker")
        if type(version_raw) is not int or not isinstance(checksum_raw, str):
            raise ExtensionControlAuthorityError("invalid extension control schema marker")
        version = version_raw
        checksum = checksum_raw
        if version != EXTENSION_CONTROL_SCHEMA_VERSION or checksum != _SCHEMA_CHECKSUM:
            raise ExtensionControlAuthorityError("unsupported or invalid extension control schema")

    _ = connection.execute(
        """
        create table if not exists extension_control_authority_snapshot (
            singleton integer primary key check (singleton = 1),
            revision integer not null check (revision >= 0),
            catalog_digest text not null,
            layers_json text not null,
            previous_digest text,
            snapshot_json text not null,
            snapshot_digest text not null,
            snapshot_mac text not null,
            committed_at text not null
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists extension_control_authority_transition (
            revision integer primary key check (revision > 0),
            previous_revision integer not null check (previous_revision >= 0),
            phase text not null check (phase in ('prepared', 'anchored', 'committed')),
            actor_id_hash text not null,
            idempotency_key_hash text not null unique,
            nonce_hash text not null unique,
            catalog_digest text not null,
            layers_json text not null,
            snapshot_json text not null,
            snapshot_digest text not null,
            snapshot_mac text not null,
            transition_json text not null,
            transition_digest text not null,
            transition_mac text not null,
            created_at text not null,
            committed_at text
        )
        """
    )
