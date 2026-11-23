"""The native base schema must match the statements the Python store runs.

The native runtime carries its own copy of the base statements
(``guard_store_schema_base_a.rs`` and ``_b.rs``). This
test reads both and requires the same statements in the same order, so a
change to either side fails until the other follows.
"""

from __future__ import annotations

import re
import sqlite3
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard.store_base_schema import base_schema_statements

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust" / "crates" / "guard-runtime" / "src"
RUST_FILES = ("guard_store_schema_base_a.rs", "guard_store_schema_base_b.rs")
RAW_STRING = re.compile(r'r##"(.*?)"##', re.S)


def _python_statements() -> list[str]:
    return [textwrap.dedent(statement).strip() for statement in base_schema_statements()]


def _native_statements() -> list[str]:
    statements: list[str] = []
    for name in RUST_FILES:
        statements.extend(RAW_STRING.findall((RUST / name).read_text(encoding="utf-8")))
    return statements


def _objects(statements: list[str]) -> list[tuple[str, str, str]]:
    connection = sqlite3.connect(":memory:")
    try:
        for statement in statements:
            connection.executescript(statement)
        rows = connection.execute(
            "select type, name, coalesce(sql, '') from sqlite_master where name not like 'sqlite_%' order by type, name"
        ).fetchall()
    finally:
        connection.close()
    return [(str(kind), str(name), " ".join(str(sql).split())) for kind, name, sql in rows]


def test_native_base_statements_match_the_python_list() -> None:
    assert _native_statements() == _python_statements()


def test_native_base_statements_create_the_python_schema() -> None:
    assert _objects(_native_statements()) == _objects(_python_statements())
