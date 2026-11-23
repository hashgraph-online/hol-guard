"""The native activity maintenance, API and display schemas must match Python.

The native runtime keeps its own copy of these statements
(``guard_store_schema_activity_extra_sql.rs``) and their versions
(``guard_store_schema_activity_extra.rs``). This test reads those files and
requires the same statements in the same order, so a change to either side
fails until the other follows.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_command_activity_api_schema as api
from codex_plugin_scanner.guard import store_command_activity_display_schema as display
from codex_plugin_scanner.guard import store_command_activity_maintenance_schema as maintenance

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "rust" / "crates" / "guard-runtime" / "src"
RAW_STRING = re.compile(r'r##"(.*?)"##', re.S)


def _rust_block(file_name: str, name: str) -> str:
    source = (SOURCE / file_name).read_text(encoding="utf-8")
    match = re.search(rf'const {name}: [^=]+=\s*(\[.*?\n\]|r##".*?"##|[^;]*);\n', source, re.S)
    assert match is not None, name
    return match.group(1)


def _statements(name: str) -> list[str]:
    return [
        re.sub(r"\?1\b", "?", text)
        for text in RAW_STRING.findall(_rust_block("guard_store_schema_activity_extra_sql.rs", name))
    ]


def _python(statement: str) -> str:
    return textwrap.dedent(statement).strip()


def test_native_statements_match_the_python_statements() -> None:
    pairs = {
        "MAINTENANCE_STATEMENTS": maintenance.command_activity_maintenance_schema_statements(),
        "MAINTENANCE_SEED": (maintenance.MAINTENANCE_SEED_SQL,),
        "API_STATEMENTS": api.command_activity_api_schema_statements(),
        "DISPLAY_STATEMENTS": display.command_activity_display_schema_statements(),
    }
    for name, statements in pairs.items():
        assert _statements(name) == [_python(statement) for statement in statements], name


def test_native_versions_match_the_python_versions() -> None:
    def version(name: str) -> str:
        return _rust_block("guard_store_schema_activity_extra.rs", name).strip().strip('"')

    assert version("MAINTENANCE_VERSION") == str(maintenance.COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_MIGRATION_VERSION)
    assert version("MAINTENANCE_SCHEMA_VERSION") == maintenance.COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION
    assert version("API_VERSION") == str(api.COMMAND_ACTIVITY_API_SCHEMA_MIGRATION_VERSION)
    assert version("DISPLAY_VERSION") == str(display.COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION)


def test_the_maintenance_seed_still_creates_a_valid_singleton() -> None:
    import sqlite3

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
    connection.execute("create table command_activity (activity_id text primary key, occurred_at text)")
    maintenance.ensure_command_activity_maintenance_schema(connection, applied_at="2026-01-02T03:04:05+00:00")
    row = connection.execute("select schema_version from command_activity_maintenance").fetchone()
    assert row["schema_version"] == maintenance.COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION
