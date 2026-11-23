"""The native local-CLI schema must match the statements Python runs.

The native runtime keeps its own copy of the local-CLI statements
(``guard_store_schema_local_cli_sql.rs``). These tests require every native
statement to appear in the Python modules, and a fresh store built from the
native statements to have the same tables as one ``ensure_local_cli_schema``
builds, so a change to either side fails until the other follows.
"""

from __future__ import annotations

import hashlib
import inspect
import re
import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard import store_local_cli_capabilities as capabilities
from codex_plugin_scanner.guard import store_local_cli_context as context
from codex_plugin_scanner.guard import store_local_cli_schema as schema

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "rust" / "crates" / "guard-runtime" / "src"
SQL = SRC / "guard_store_schema_local_cli_sql.rs"
STEP = SRC / "guard_store_schema_local_cli.rs"
# The order ``ensure_local_cli_schema`` creates a fresh store's objects in.
FRESH = (
    "MIGRATION_TABLE",
    "OBSERVATION_TABLE",
    "GRANT_TABLE",
    "AUTHORITY_TABLE",
    "AUTHORITY_SEED",
    "COMMAND_TABLES",
    "TOOL_AUTHORITY_TABLE",
    "WORKFLOW_PROPOSAL_TABLE",
    "CATALOG_TABLE",
    "PROVIDER_GRANT_TABLE",
    "PROVIDER_AUTHORITY_TABLE",
    "PROVIDER_ACTION_TABLE",
    "CAPABILITY_TABLE",
)


def _normal(text: str) -> str:
    return " ".join(re.sub(r"\?\d", "?", text).split())


def _rust_strings(block: str) -> list[str]:
    return [raw or plain for raw, plain in re.findall(r'r##"(.*?)"##|"((?:[^"\\]|\\.)*)"', block, re.S)]


def _rust_block(name: str) -> str:
    source = SQL.read_text(encoding="utf-8")
    match = re.search(rf'const {name}: [^=]+=\s*(\[.*?\n\]|\[[^\n]*\]|r##".*?"##|[^;]*);\n', source, re.S)
    assert match is not None, name
    return match.group(1)


def _python_source() -> str:
    source = "\n".join(inspect.getsource(module) for module in (schema, capabilities, context))
    # Join implicitly concatenated literals that a statement spans.
    return _normal(re.sub(r'"\s*\n\s*"', "", source))


def test_every_native_statement_is_a_python_statement() -> None:
    python = _python_source()
    statements = [
        statement
        for raw, plain in re.findall(
            r'r##"(.*?)"##|"((?:[^"\\]|\\.)*)"\s*[,;\]]', SQL.read_text(encoding="utf-8"), re.S
        )
        for statement in (raw or plain,)
        if " " in statement
    ]
    assert len(statements) > 20
    missing = [statement for statement in statements if _normal(statement) not in python]
    assert missing == []


def test_a_fresh_native_store_has_the_python_tables() -> None:
    python = sqlite3.connect(":memory:")
    schema.ensure_local_cli_schema(python)
    native = sqlite3.connect(":memory:")
    for name in FRESH:
        for statement in _rust_strings(_rust_block(name)):
            native.execute(statement.replace("?1", "?").replace("?2", "?"))
    for column, kind in re.findall(r'\("(\w+)", "(\w+)"\)', _rust_block("CONTEXT_COLUMNS")):
        native.execute(f"alter table local_cli_observation add column {column} {kind}")

    def shape(connection: sqlite3.Connection) -> list[tuple[str, str]]:
        rows = connection.execute("select name, sql from sqlite_master order by name").fetchall()
        return [(name, _normal(sql or "")) for name, sql in rows]

    assert shape(native) == shape(python)
    assert native.execute("select * from local_cli_authority").fetchall() == [(1, 0)]


def test_native_context_columns_match_the_python_columns() -> None:
    columns = re.findall(r'\("(\w+)", "text"\)', _rust_block("CONTEXT_COLUMNS"))
    assert tuple(columns) == context.CONTEXT_COLUMNS


def test_native_marker_matches_the_python_marker() -> None:
    step = STEP.read_text(encoding="utf-8")
    assert f"pub(super) const VERSION: i64 = {schema.LOCAL_CLI_SCHEMA_VERSION};" in step
    assert 'format!("hol-guard.local-cli-allowlist.schema.v{version}")' in step
    seed = f"hol-guard.local-cli-allowlist.schema.v{schema.LOCAL_CLI_SCHEMA_VERSION}".encode()
    assert hashlib.sha256(seed).hexdigest() == schema._SCHEMA_CHECKSUM  # pyright: ignore[reportPrivateUsage]


def test_native_migration_columns_match_the_python_migrations() -> None:
    python = _python_source()
    for name in ("V2_COLUMNS", "V3_COLUMNS", "V5_COLUMNS"):
        for column, kind in re.findall(r'\("(\w+)", "([^"]+)"\)', _rust_block(name)):
            assert _normal(f"add column {column} {kind}") in python, (name, column)
    v12 = re.findall(r'\("(\w+)", "text"\)', _rust_block("V12_COLUMNS"))
    assert v12 == ["remote_origin", "declared_sources_json"]
    assert 'for column in ("remote_origin", "declared_sources_json"):' in inspect.getsource(schema)
