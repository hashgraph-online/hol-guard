"""The native policy-request schema must match the statements Python runs.

The native runtime keeps its own copy of the policy-request table and indexes
(``guard_store_schema_requests.rs``). This test reads that file and requires
the same statements in the same order, so a change to either side fails until
the other follows.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard.mcp import policy_store

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_requests.rs"


def _rust_block(name: str) -> str:
    source = SOURCE.read_text(encoding="utf-8")
    match = re.search(rf'const {name}: [^=]+=\s*(\[.*?\n\]|r##".*?"##|[^;]*);\n', source, re.S)
    assert match is not None, name
    return match.group(1)


def test_native_request_table_matches_the_python_table() -> None:
    table = re.fullmatch(r'r##"(.*)"##', _rust_block("MCP_POLICY_REQUEST_TABLE"), re.S)
    assert table is not None
    python_table = policy_store._MCP_POLICY_REQUEST_SCHEMA  # pyright: ignore[reportPrivateUsage]
    assert table.group(1) == textwrap.dedent(python_table).strip()


def test_native_request_indexes_match_the_python_indexes() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    declared = re.search(r"const MCP_POLICY_REQUEST_INDEXES: \[&str; (\d+)\]", source)
    assert declared is not None
    statements = re.findall(r'"(create index[^"]*)"', _rust_block("MCP_POLICY_REQUEST_INDEXES"))
    assert len(statements) == int(declared.group(1))
    python_indexes = policy_store._MCP_POLICY_REQUEST_INDEXES  # pyright: ignore[reportPrivateUsage]
    assert statements == list(python_indexes)


def test_native_steps_follow_the_python_order() -> None:
    """The native run keeps the order the store opener runs these steps in."""
    source = SOURCE.read_text(encoding="utf-8")
    body = source[source.index("fn ensure_requests_through_approvals") :]
    names = (
        "MCP_POLICY_REQUEST_TABLE",
        "MCP_POLICY_REQUEST_INDEXES",
        "record_version(connection, 4",
        "create_cache_indexes",
        "upgrade_policy_decisions",
        "upgrade_runtime_receipts",
        "upgrade_receipt_envelopes",
        "upgrade_approval_requests",
    )
    steps = re.findall("(" + "|".join(re.escape(name) for name in names) + ")", body)
    assert steps == [
        "MCP_POLICY_REQUEST_TABLE",
        "MCP_POLICY_REQUEST_INDEXES",
        "record_version(connection, 4",
        "create_cache_indexes",
        "upgrade_policy_decisions",
        "upgrade_runtime_receipts",
        "upgrade_receipt_envelopes",
        "upgrade_approval_requests",
    ]
    opener = (ROOT / "src" / "codex_plugin_scanner" / "guard" / "store_connection_schema.py").read_text(
        encoding="utf-8"
    )
    python_order = [
        "ensure_mcp_policy_request_schema(connection)",
        "self._record_schema_version(connection, version=4)",
        "supply_chain_index_statements()",
        'ensure_columns(connection, "policy_decisions"',
        'ensure_columns(connection, "runtime_receipts"',
        "migrate_v5_receipt_envelopes(connection)",
        'ensure_columns(connection, "approval_requests"',
    ]
    positions = [opener.index(step) for step in python_order]
    assert positions == sorted(positions)
