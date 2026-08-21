"""Forward-only SQLite schema for unlisted CLI observations and grants."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Final, cast

LOCAL_CLI_SCHEMA_VERSION: Final = 4
_V1_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v1").hexdigest()
_V2_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v2").hexdigest()
_V3_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v3").hexdigest()
_SCHEMA_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v4").hexdigest()


class LocalCliSchemaError(ValueError):
    """The persisted local-CLI schema cannot be safely interpreted by this runtime.

    Distinguishing the failure mode matters for recovery: a store written by a
    newer Guard is healthy and only needs an update, while a marker that does
    not match any known schema signals damage or tampering. Both stay
    fail-closed; only the remediation differs.
    """

    def __init__(self, message: str, *, store_version: int | None, supported_version: int) -> None:
        super().__init__(message)
        self.store_version = store_version
        self.supported_version = supported_version


def ensure_local_cli_schema(connection: sqlite3.Connection) -> None:
    _ = connection.execute(
        """
        create table if not exists local_cli_schema_migration (
            singleton integer primary key check (singleton = 1),
            version integer not null,
            checksum text not null
        )
        """
    )
    row = cast(
        object,
        connection.execute("select version, checksum from local_cli_schema_migration where singleton = 1").fetchone(),
    )
    if row is None:
        _ = connection.execute(
            "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?, ?)",
            (LOCAL_CLI_SCHEMA_VERSION, _SCHEMA_CHECKSUM),
        )
    else:
        version, checksum = _marker(row)
        if version == 1 and checksum == _V1_CHECKSUM:
            _migrate_v1_to_v2(connection)
            version, checksum = 2, _V2_CHECKSUM
        if version == 2 and checksum == _V2_CHECKSUM:
            _migrate_v2_to_v3(connection)
            version, checksum = 3, _V3_CHECKSUM
        if version == 3 and checksum == _V3_CHECKSUM:
            _migrate_v3_to_v4(connection)
        elif version != LOCAL_CLI_SCHEMA_VERSION or checksum != _SCHEMA_CHECKSUM:
            if version > LOCAL_CLI_SCHEMA_VERSION:
                raise LocalCliSchemaError(
                    f"local CLI state schema v{version} is newer than this Guard build "
                    f"understands (v{LOCAL_CLI_SCHEMA_VERSION}); update Guard and retry",
                    store_version=version,
                    supported_version=LOCAL_CLI_SCHEMA_VERSION,
                )
            raise LocalCliSchemaError(
                f"local CLI state schema marker does not match this Guard build "
                f"(supports v{LOCAL_CLI_SCHEMA_VERSION}); the store may be damaged or "
                "come from an unsupported build",
                store_version=version,
                supported_version=LOCAL_CLI_SCHEMA_VERSION,
            )
    _ = connection.execute(
        """
        create table if not exists local_cli_observation (
            cli_id text primary key,
            identity_hash text not null,
            kind text not null check (kind in ('executable', 'script')),
            name text not null,
            interpreter_name text,
            example_label text not null,
            observed_count integer not null check (observed_count >= 1),
            last_seen_at text not null,
            source_path text,
            help_status text,
            surface text not null default 'cli' check (surface in ('cli', 'mcp', 'package-scripts')),
            server_identity_hash text,
            server_command text,
            server_args_hash text
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists local_cli_grant (
            cli_id text primary key,
            identity_hash text not null,
            state text not null check (state in ('allowed', 'blocked')),
            revision integer not null check (revision >= 1),
            updated_at text not null
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists local_cli_authority (
            singleton integer primary key check (singleton = 1),
            revision integer not null check (revision >= 0)
        )
        """
    )
    _ = connection.execute("insert or ignore into local_cli_authority (singleton, revision) values (1, 0)")
    _ensure_command_tables(connection)


def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
    columns = _table_column_names(connection, "local_cli_observation")
    if "source_path" not in columns:
        _ = connection.execute("alter table local_cli_observation add column source_path text")
    if "help_status" not in columns:
        _ = connection.execute("alter table local_cli_observation add column help_status text")
    _ensure_command_tables(connection)
    _ = connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (2, _V2_CHECKSUM),
    )


def _migrate_v2_to_v3(connection: sqlite3.Connection) -> None:
    columns = _table_column_names(connection, "local_cli_observation")
    if "surface" not in columns:
        _ = connection.execute("alter table local_cli_observation add column surface text not null default 'cli'")
    if "server_identity_hash" not in columns:
        _ = connection.execute("alter table local_cli_observation add column server_identity_hash text")
    if "server_command" not in columns:
        _ = connection.execute("alter table local_cli_observation add column server_command text")
    if "server_args_hash" not in columns:
        _ = connection.execute("alter table local_cli_observation add column server_args_hash text")
    _ = connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (3, _V3_CHECKSUM),
    )


def _migrate_v3_to_v4(connection: sqlite3.Connection) -> None:
    _ = connection.execute("alter table local_cli_observation rename to local_cli_observation_v3")
    _ = connection.execute(
        """
        create table local_cli_observation (
            cli_id text primary key,
            identity_hash text not null,
            kind text not null check (kind in ('executable', 'script')),
            name text not null,
            interpreter_name text,
            example_label text not null,
            observed_count integer not null check (observed_count >= 1),
            last_seen_at text not null,
            source_path text,
            help_status text,
            surface text not null default 'cli' check (surface in ('cli', 'mcp', 'package-scripts')),
            server_identity_hash text,
            server_command text,
            server_args_hash text
        )
        """
    )
    _ = connection.execute(
        """
        insert into local_cli_observation (
            cli_id, identity_hash, kind, name, interpreter_name, example_label,
            observed_count, last_seen_at, source_path, help_status, surface,
            server_identity_hash, server_command, server_args_hash
        )
        select
            cli_id, identity_hash, kind, name, interpreter_name, example_label,
            observed_count, last_seen_at, source_path, help_status, surface,
            server_identity_hash, server_command, server_args_hash
        from local_cli_observation_v3
        """
    )
    _ = connection.execute("drop table local_cli_observation_v3")
    _ = connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (LOCAL_CLI_SCHEMA_VERSION, _SCHEMA_CHECKSUM),
    )


def _ensure_command_tables(connection: sqlite3.Connection) -> None:
    _ = connection.execute(
        """
        create table if not exists local_cli_command (
            cli_id text not null,
            command_id text not null,
            name text not null,
            usage text not null,
            description text not null,
            parent_id text,
            sort_index integer not null check (sort_index >= 0),
            primary key (cli_id, command_id)
        )
        """
    )
    _ = connection.execute(
        """
        create table if not exists local_cli_command_grant (
            cli_id text not null,
            command_id text not null,
            state text not null check (state in ('inherit', 'allow', 'block')),
            primary key (cli_id, command_id)
        )
        """
    )


def _table_column_names(connection: sqlite3.Connection, table: str) -> set[str]:
    names: set[str] = set()
    for row in connection.execute(f"pragma table_info({table})").fetchall():
        if isinstance(row, sqlite3.Row):
            names.add(str(row["name"]))
            continue
        if isinstance(row, tuple) and len(row) > 1:
            names.add(str(row[1]))
    return names


def _marker(row: object) -> tuple[int, str]:
    if isinstance(row, sqlite3.Row):
        version_raw = cast(object, row["version"])
        checksum_raw = cast(object, row["checksum"])
    elif isinstance(row, tuple):
        values = cast(tuple[object, ...], row)
        if len(values) != 2:
            raise ValueError("invalid local CLI schema marker")
        version_raw, checksum_raw = values
    else:
        raise ValueError("invalid local CLI schema marker")
    if type(version_raw) is not int or not isinstance(checksum_raw, str):
        raise ValueError("invalid local CLI schema marker")
    return version_raw, checksum_raw
