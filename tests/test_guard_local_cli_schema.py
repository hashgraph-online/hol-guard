from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store_local_cli_schema import (
    _V1_CHECKSUM,
    _V2_CHECKSUM,
    _V3_CHECKSUM,
    LocalCliSchemaError,
    LOCAL_CLI_SCHEMA_VERSION,
    ensure_local_cli_schema,
)


def test_v1_schema_migrates_to_command_tables(tmp_path: Path) -> None:
    db = tmp_path / "guard.db"
    connection = sqlite3.connect(db)
    connection.execute(
        """
        create table local_cli_schema_migration (
            singleton integer primary key,
            version integer not null,
            checksum text not null
        )
        """
    )
    connection.execute(
        "insert into local_cli_schema_migration (singleton, version, checksum) values (1, 1, ?)",
        (_V1_CHECKSUM,),
    )
    connection.execute(
        """
        create table local_cli_observation (
            cli_id text primary key,
            identity_hash text not null,
            kind text not null,
            name text not null,
            interpreter_name text,
            example_label text not null,
            observed_count integer not null,
            last_seen_at text not null
        )
        """
    )
    connection.commit()
    ensure_local_cli_schema(connection)
    version, _checksum = connection.execute(
        "select version, checksum from local_cli_schema_migration where singleton = 1"
    ).fetchone()
    assert version == LOCAL_CLI_SCHEMA_VERSION
    tables = {row[0] for row in connection.execute("select name from sqlite_master where type = 'table'").fetchall()}
    assert "local_cli_command" in tables
    assert "local_cli_command_grant" in tables
    columns = {row[1] for row in connection.execute("pragma table_info(local_cli_observation)").fetchall()}
    assert "surface" in columns
    assert "server_identity_hash" in columns
    connection.close()


def test_v2_schema_migrates_to_mcp_surface(tmp_path: Path) -> None:
    db = tmp_path / "guard.db"
    connection = sqlite3.connect(db)
    connection.execute(
        """
        create table local_cli_schema_migration (
            singleton integer primary key,
            version integer not null,
            checksum text not null
        )
        """
    )
    connection.execute(
        "insert into local_cli_schema_migration (singleton, version, checksum) values (1, 2, ?)",
        (_V2_CHECKSUM,),
    )
    connection.execute(
        """
        create table local_cli_observation (
            cli_id text primary key,
            identity_hash text not null,
            kind text not null,
            name text not null,
            interpreter_name text,
            example_label text not null,
            observed_count integer not null,
            last_seen_at text not null,
            source_path text,
            help_status text
        )
        """
    )
    connection.commit()
    ensure_local_cli_schema(connection)
    version, _checksum = connection.execute(
        "select version, checksum from local_cli_schema_migration where singleton = 1"
    ).fetchone()
    assert version == LOCAL_CLI_SCHEMA_VERSION
    columns = {row[1] for row in connection.execute("pragma table_info(local_cli_observation)").fetchall()}
    assert "surface" in columns
    assert "server_identity_hash" in columns
    connection.close()


def test_v3_schema_accepts_package_scripts_surface(tmp_path: Path) -> None:
    db = tmp_path / "guard.db"
    connection = sqlite3.connect(db)
    connection.execute(
        """
        create table local_cli_schema_migration (
            singleton integer primary key,
            version integer not null,
            checksum text not null
        )
        """
    )
    connection.execute(
        "insert into local_cli_schema_migration (singleton, version, checksum) values (1, 3, ?)",
        (_V3_CHECKSUM,),
    )
    connection.execute(
        """
        create table local_cli_observation (
            cli_id text primary key,
            identity_hash text not null,
            kind text not null,
            name text not null,
            interpreter_name text,
            example_label text not null,
            observed_count integer not null,
            last_seen_at text not null,
            source_path text,
            help_status text,
            surface text not null default 'cli' check (surface in ('cli', 'mcp')),
            server_identity_hash text,
            server_command text,
            server_args_hash text
        )
        """
    )
    connection.execute(
        """
        insert into local_cli_observation (
            cli_id, identity_hash, kind, name, example_label, observed_count, last_seen_at, surface
        ) values ('local-cli.demo-abcdef12', ?, 'script', 'demo', 'demo', 1, '2026-08-20T00:00:00Z', 'cli')
        """,
        ("b" * 64,),
    )
    connection.commit()
    ensure_local_cli_schema(connection)
    version, _checksum = connection.execute(
        "select version, checksum from local_cli_schema_migration where singleton = 1"
    ).fetchone()
    assert version == LOCAL_CLI_SCHEMA_VERSION
    connection.execute(
        """
        insert into local_cli_observation (
            cli_id, identity_hash, kind, name, example_label,
            observed_count, last_seen_at, surface
        ) values (
            'local-cli.pkg-demo-abcdef12', ?, 'script', 'demo-app',
            'pnpm run', 1, '2026-08-20T00:00:00Z', 'package-scripts'
        )
        """,
        ("a" * 64,),
    )
    surface = connection.execute(
        "select surface from local_cli_observation where cli_id = 'local-cli.pkg-demo-abcdef12'"
    ).fetchone()[0]
    assert surface == "package-scripts"
    connection.close()


def _store_with_schema_marker(tmp_path: Path, version: int, checksum: str) -> sqlite3.Connection:
    connection = sqlite3.connect(tmp_path / "guard.db")
    connection.execute(
        """
        create table local_cli_schema_migration (
            singleton integer primary key,
            version integer not null,
            checksum text not null
        )
        """
    )
    connection.execute(
        "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?, ?)",
        (version, checksum),
    )
    connection.commit()
    return connection


def test_newer_store_schema_names_the_update_recovery(tmp_path: Path) -> None:
    connection = _store_with_schema_marker(
        tmp_path,
        version=LOCAL_CLI_SCHEMA_VERSION + 1,
        checksum="0" * 64,
    )

    with pytest.raises(LocalCliSchemaError) as error:
        ensure_local_cli_schema(connection)

    message = str(error.value)
    assert f"v{LOCAL_CLI_SCHEMA_VERSION + 1}" in message
    assert "newer than this Guard build" in message
    assert "update Guard" in message
    assert error.value.store_version == LOCAL_CLI_SCHEMA_VERSION + 1
    assert error.value.supported_version == LOCAL_CLI_SCHEMA_VERSION
    assert isinstance(error.value, ValueError)
    connection.close()


def test_tampered_current_schema_marker_reports_integrity_failure(tmp_path: Path) -> None:
    connection = _store_with_schema_marker(
        tmp_path,
        version=LOCAL_CLI_SCHEMA_VERSION,
        checksum="0" * 64,
    )

    with pytest.raises(LocalCliSchemaError) as error:
        ensure_local_cli_schema(connection)

    message = str(error.value)
    assert "does not match this Guard build" in message
    assert "newer than" not in message
    assert error.value.store_version == LOCAL_CLI_SCHEMA_VERSION
    assert error.value.supported_version == LOCAL_CLI_SCHEMA_VERSION
    connection.close()


def test_unknown_older_store_schema_reports_integrity_failure(tmp_path: Path) -> None:
    connection = _store_with_schema_marker(tmp_path, version=0, checksum="0" * 64)

    with pytest.raises(LocalCliSchemaError) as error:
        ensure_local_cli_schema(connection)

    assert "does not match this Guard build" in str(error.value)
    assert error.value.store_version == 0
    connection.close()
