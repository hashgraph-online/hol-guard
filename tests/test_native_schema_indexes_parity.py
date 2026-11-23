"""The native index and table statements must match the Python lists.

``guard_store_schema_indexes.rs`` keeps a copy of each statement list the
store runs after its column upgrades. This test reads that file and requires
the same statements in the same order as the Python function each constant
names, so a change to either side fails until the other follows.
"""

from __future__ import annotations

import re
import sqlite3
import textwrap
from collections.abc import Callable, Sequence
from pathlib import Path

from codex_plugin_scanner.guard.store_approvals import approval_index_statements
from codex_plugin_scanner.guard.store_base import receipt_index_statements
from codex_plugin_scanner.guard.store_base_schema import base_schema_statements
from codex_plugin_scanner.guard.store_receipt_rollup_schema import (
    receipt_rollup_index_statements,
    receipt_rollup_schema_statements,
)
from codex_plugin_scanner.guard.store_schema_columns import (
    APPROVAL_COLUMNS,
    RECEIPT_COLUMNS,
    ensure_columns,
)
from codex_plugin_scanner.guard.store_storage_maintenance import storage_maintenance_schema_statements
from codex_plugin_scanner.guard.store_supply_chain import supply_chain_index_statements
from codex_plugin_scanner.guard.store_threat_intel import threat_intel_index_statements

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_indexes.rs"
RAW_STRING = re.compile(r'r##"(.*?)"##', re.S)
LISTS: dict[str, Callable[[], Sequence[str]]] = {
    "SUPPLY_CHAIN_INDEXES": supply_chain_index_statements,
    "THREAT_INTEL_INDEXES": threat_intel_index_statements,
    "APPROVAL_INDEXES": approval_index_statements,
    "RECEIPT_INDEXES": receipt_index_statements,
    "RECEIPT_ROLLUP_TABLES": receipt_rollup_schema_statements,
    "RECEIPT_ROLLUP_INDEXES": receipt_rollup_index_statements,
    "STORAGE_MAINTENANCE": storage_maintenance_schema_statements,
}


def _native(name: str) -> list[str]:
    source = RUST.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+= \[(.*?)\n\];", source, re.S)
    assert match is not None, name
    return RAW_STRING.findall(match.group(1))


def test_every_native_list_matches_its_python_list() -> None:
    for name, statements in LISTS.items():
        assert _native(name) == [textwrap.dedent(statement).strip() for statement in statements()], name


def test_the_native_statements_run_on_the_upgraded_tables() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        for statement in base_schema_statements():
            connection.executescript(statement)
        ensure_columns(connection, "runtime_receipts", RECEIPT_COLUMNS)
        ensure_columns(connection, "approval_requests", APPROVAL_COLUMNS)
        for name in LISTS:
            for statement in _native(name):
                connection.executescript(statement)
        rows = connection.execute("select count(*) from guard_storage_maintenance").fetchone()
    finally:
        connection.close()
    assert rows == (1,)
