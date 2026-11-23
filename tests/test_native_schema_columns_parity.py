"""The native column upgrades must match the lists the Python store runs.

The native runtime keeps its own copy of the column lists and the policy
indexes (``guard_store_schema_columns.rs``). This test reads that file and
requires the same entries in the same order, so a change to either side fails
until the other follows.
"""

from __future__ import annotations

import re
import sqlite3
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_schema_columns as columns

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_columns.rs"
LISTS = ("POLICY_COLUMNS", "LOCAL_ONCE_COLUMNS", "RECEIPT_COLUMNS", "APPROVAL_COLUMNS", "ATTACHMENT_COLUMNS")
PAIR = re.compile(r'\("([^"]+)",\s*"([^"]+)"\)')
RAW_STRING = re.compile(r'r##"(.*?)"##', re.S)


def _rust_block(name: str) -> str:
    source = RUST.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+= (.*?);\n", source, re.S)
    assert match is not None, name
    return match.group(1)


def test_native_column_lists_match_the_python_lists() -> None:
    for name in LISTS:
        native = PAIR.findall(_rust_block(name))
        assert native == [tuple(pair) for pair in getattr(columns, name)], name


def test_native_policy_indexes_match_the_python_statements() -> None:
    native = RAW_STRING.findall(_rust_block("POLICY_INDEXES"))
    assert native == [textwrap.dedent(statement).strip() for statement in columns.POLICY_INDEX_STATEMENTS]
    local_once = RAW_STRING.findall(_rust_block("LOCAL_ONCE_INDEX"))
    assert local_once == [textwrap.dedent(columns.LOCAL_ONCE_INDEX_STATEMENT).strip()]


def test_ensure_columns_adds_only_missing_columns_in_order() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table runtime_receipts (receipt_id text primary key, diff_summary text)")
        columns.ensure_columns(connection, "runtime_receipts", columns.RECEIPT_COLUMNS)
        columns.ensure_columns(connection, "runtime_receipts", columns.RECEIPT_COLUMNS)
        names = [str(row[1]) for row in connection.execute("pragma table_info(runtime_receipts)")]
    finally:
        connection.close()
    expected = ["receipt_id", "diff_summary"] + [name for name, _ in columns.RECEIPT_COLUMNS if name != "diff_summary"]
    assert names == expected
