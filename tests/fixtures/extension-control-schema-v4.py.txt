"""Forward-only SQLite schema for extension-control authority records."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Final, cast

from .runtime.extension_control_authority import ExtensionControlAuthorityError

EXTENSION_CONTROL_SCHEMA_VERSION: Final = 4
_SCHEMA_CHECKSUM_V1: Final = hashlib.sha256(b"hol-guard.extension-control-authority.schema.v1").hexdigest()
_SCHEMA_CHECKSUM_V2: Final = hashlib.sha256(b"hol-guard.extension-control-authority.schema.v2").hexdigest()
_SCHEMA_CHECKSUM_V3: Final = hashlib.sha256(b"hol-guard.extension-control-authority.schema.v3").hexdigest()
_SCHEMA_CHECKSUM: Final = hashlib.sha256(b"hol-guard.extension-control-authority.schema.v4").hexdigest()


def extension_control_schema_marker_is_compatible(
    version: object,
    checksum: object,
) -> bool:
    if type(version) is not int or not isinstance(checksum, str):
        return False
    return (version, checksum) in {
        (1, _SCHEMA_CHECKSUM_V1),
        (2, _SCHEMA_CHECKSUM_V2),
        (3, _SCHEMA_CHECKSUM_V3),
        (EXTENSION_CONTROL_SCHEMA_VERSION, _SCHEMA_CHECKSUM),
    }


def ensure_extension_control_authority_schema(
    connection: sqlite3.Connection,
    *,
    require_compatible: bool = True,
) -> bool:
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
                if require_compatible:
                    raise ExtensionControlAuthorityError("invalid extension control schema marker")
                return False
            version_raw, checksum_raw = row_values
        else:
            raise ExtensionControlAuthorityError("invalid extension control schema marker")
        if not extension_control_schema_marker_is_compatible(version_raw, checksum_raw):
            if require_compatible:
                raise ExtensionControlAuthorityError("unsupported or invalid extension control schema")
            return False
        if type(version_raw) is int and version_raw != EXTENSION_CONTROL_SCHEMA_VERSION:
            _ = connection.execute(
                "update extension_control_schema_migration set version = ?, checksum = ? where singleton = 1",
                (EXTENSION_CONTROL_SCHEMA_VERSION, _SCHEMA_CHECKSUM),
            )

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
        create table if not exists extension_control_catalog_manifest (
            catalog_digest text primary key,
            manifest_json text not null,
            record_json text not null,
            record_digest text not null,
            record_mac text not null,
            recorded_at text not null
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists extension_control_authority_recovery_archive (
            archive_id text primary key,
            reason text not null,
            archived_at text not null,
            previous_revision integer,
            previous_catalog_digest text,
            snapshot_row_json text,
            transition_rows_json text not null,
            proof_rows_json text not null
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
    _ = connection.execute(
        """
        create table if not exists extension_control_authority_proof (
            proof_id_hash text primary key,
            mutation_digest text not null,
            transition_revision integer not null check (transition_revision > 0),
            reserved_at text not null,
            consumed_at text
        )
        """
    )
    return True
