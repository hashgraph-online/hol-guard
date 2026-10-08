"""Forward-only SQLite schema for unlisted CLI observations and grants."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Final, cast

LOCAL_CLI_SCHEMA_VERSION: Final = 11
_V1_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v1").hexdigest()
_V2_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v2").hexdigest()
_V3_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v3").hexdigest()
_V4_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v4").hexdigest()
_V5_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v5").hexdigest()
_V6_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v6").hexdigest()
_V7_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v7").hexdigest()
_V8_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v8").hexdigest()
_V9_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v9").hexdigest()
_V10_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v10").hexdigest()
_SCHEMA_CHECKSUM: Final = hashlib.sha256(b"hol-guard.local-cli-allowlist.schema.v11").hexdigest()


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


def ensure_local_cli_schema(connection: sqlite3.Connection, *, for_read: bool = False) -> None:
    if for_read:
        exists = connection.execute(
            "select 1 from sqlite_master where type = 'table' and name = 'local_cli_schema_migration'"
        ).fetchone()
        if exists is not None:
            marker = connection.execute(
                "select version, checksum from local_cli_schema_migration where singleton = 1"
            ).fetchone()
            if marker is not None and _marker(marker) == (LOCAL_CLI_SCHEMA_VERSION, _SCHEMA_CHECKSUM):
                # A current schema needs no writes. In particular, INSERT OR
                # IGNORE would acquire a writer lock on an authorization read.
                return
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
            version, checksum = 4, _V4_CHECKSUM
        if version == 4 and checksum == _V4_CHECKSUM:
            _migrate_v4_to_v5(connection)
            version, checksum = 5, _V5_CHECKSUM
        if version == 5 and checksum == _V5_CHECKSUM:
            _migrate_v5_to_v6(connection)
            version, checksum = 6, _V6_CHECKSUM
        if version == 6 and checksum == _V6_CHECKSUM:
            _migrate_v6_to_v7(connection)
            version, checksum = 7, _V7_CHECKSUM
        if version == 7 and checksum == _V7_CHECKSUM:
            _migrate_v7_to_v8(connection)
            version, checksum = 8, _V8_CHECKSUM
        if version == 8 and checksum == _V8_CHECKSUM:
            _ensure_mcp_provider_grant_table(connection)
            connection.execute(
                "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
                (9, _V9_CHECKSUM),
            )
            version, checksum = 9, _V9_CHECKSUM
        if version == 9 and checksum == _V9_CHECKSUM:
            _ensure_provider_authority_table(connection)
            from .store_mcp_provider_catalog import rebuild_provider_authority

            for cli_id, identity_hash in connection.execute(
                "select distinct cli_id, identity_hash from local_mcp_provider_action"
            ).fetchall():
                rebuild_provider_authority(connection, cli_id, identity_hash)
            connection.execute(
                "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
                (10, _V10_CHECKSUM),
            )
            version, checksum = 10, _V10_CHECKSUM
        if version == 10 and checksum == _V10_CHECKSUM:
            _ensure_mcp_tool_authority_table(connection)
            _ensure_workflow_proposal_table(connection)
            from .store_mcp_catalog import rebuild_tool_authority

            for cli_id, identity_hash, raw, revision in connection.execute(
                "select cli_id, identity_hash, catalog_json, revision from local_mcp_catalog"
            ).fetchall():
                rebuild_tool_authority(connection, cli_id, identity_hash, raw, revision)
            connection.execute(
                "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
                (11, _SCHEMA_CHECKSUM),
            )
            version, checksum = 11, _SCHEMA_CHECKSUM
        if version != LOCAL_CLI_SCHEMA_VERSION or checksum != _SCHEMA_CHECKSUM:
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
            server_args_hash text,
            source_label text
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
    _ensure_mcp_catalog_table(connection)
    _ensure_mcp_provider_catalog_table(connection)


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
        (4, _V4_CHECKSUM),
    )


def _migrate_v4_to_v5(connection: sqlite3.Connection) -> None:
    columns = _table_column_names(connection, "local_cli_observation")
    if "source_label" not in columns:
        _ = connection.execute("alter table local_cli_observation add column source_label text")
    _ = connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (5, _V5_CHECKSUM),
    )


def _migrate_v5_to_v6(connection: sqlite3.Connection) -> None:
    _ensure_mcp_catalog_table(connection)
    _ = connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (6, _V6_CHECKSUM),
    )


def _migrate_v6_to_v7(connection: sqlite3.Connection) -> None:
    _ensure_command_tables(connection)
    _ = connection.execute("alter table local_cli_command_grant rename to local_cli_command_grant_v6")
    _ensure_command_tables(connection)
    _ = connection.execute(
        "insert into local_cli_command_grant (cli_id, command_id, state) "
        "select cli_id, command_id, state from local_cli_command_grant_v6"
    )
    _ = connection.execute("drop table local_cli_command_grant_v6")
    _ = connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (7, _V7_CHECKSUM),
    )


def _migrate_v7_to_v8(connection: sqlite3.Connection) -> None:
    _ensure_mcp_provider_catalog_table(connection)
    connection.execute(
        "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
        (8, _V8_CHECKSUM),
    )


def _ensure_mcp_provider_catalog_table(connection: sqlite3.Connection) -> None:
    _ensure_mcp_provider_grant_table(connection)
    _ensure_provider_authority_table(connection)
    connection.execute(
        """create table if not exists local_mcp_provider_action (
            cli_id text not null,
            identity_hash text not null,
            provider text not null check (provider = 'composio'),
            tool_slug text not null,
            toolkit text not null,
            description text not null,
            input_schema_json text not null,
            authority_hash text not null,
            full_schema integer not null check (full_schema in (0, 1)),
            source_tool text not null,
            revision integer not null check (revision >= 1),
            updated_at text not null,
            primary key (cli_id, identity_hash, provider, tool_slug)
        )"""
    )


def _ensure_mcp_provider_grant_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """create table if not exists local_mcp_provider_grant (
            cli_id text not null,
            identity_hash text not null,
            tool_slug text not null,
            state text not null check (state in ('review', 'block')),
            updated_at text not null,
            primary key (cli_id, identity_hash, tool_slug)
        )"""
    )


def _ensure_provider_authority_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """create table if not exists local_mcp_provider_authority (
            cli_id text not null, identity_hash text not null, digest text not null,
            primary key (cli_id, identity_hash)
        )"""
    )


def _ensure_mcp_catalog_table(connection: sqlite3.Connection) -> None:
    _ensure_mcp_tool_authority_table(connection)
    _ensure_workflow_proposal_table(connection)
    _ = connection.execute(
        """
        create table if not exists local_mcp_catalog (
            cli_id text primary key,
            identity_hash text not null,
            catalog_json text not null,
            revision integer not null check (revision >= 1),
            updated_at text not null,
            last_complete_at text
        )
        """
    )


def _ensure_mcp_tool_authority_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """create table if not exists local_mcp_tool_authority (
            cli_id text not null, identity_hash text not null, tool_name text not null,
            catalog_revision integer not null, authority_hash text not null,
            primary key (cli_id, identity_hash, tool_name)
        )"""
    )


def _ensure_workflow_proposal_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """create table if not exists local_mcp_workflow_proposal (
            cli_id text not null, identity_hash text not null, proposal_id text not null,
            proposal_json text not null, seen_at text not null,
            primary key (cli_id, identity_hash, proposal_id)
        )"""
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
            state text not null check (state in ('inherit', 'allow', 'review', 'block')),
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
