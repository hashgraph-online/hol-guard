from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard.store_local_cli_schema import (
    _V1_CHECKSUM,
    _V2_CHECKSUM,
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
