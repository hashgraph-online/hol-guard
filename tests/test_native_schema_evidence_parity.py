"""The native evidence schema must match the statements Python runs.

The native runtime keeps its own copy of the evidence table and indexes
(``guard_store_schema_evidence_sql.rs``). This test reads that file and
requires the same statements in the same order, so a change to either side
fails until the other follows.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_evidence as evidence

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_evidence_sql.rs"


def _rust_block(name: str) -> str:
    source = SOURCE.read_text(encoding="utf-8")
    match = re.search(rf'const {name}: [^=]+=\s*(\[.*?\n\]|r##".*?"##|[^;]*);\n', source, re.S)
    assert match is not None, name
    return match.group(1)


def test_native_evidence_table_matches_the_python_table() -> None:
    table = re.fullmatch(r'r##"(.*)"##', _rust_block("EVIDENCE_TABLE"), re.S)
    assert table is not None
    assert table.group(1) == textwrap.dedent(evidence.evidence_schema_statement()).strip()


def test_native_evidence_indexes_match_the_python_indexes() -> None:
    assert re.findall(r'"(create index[^"]*)"', _rust_block("EVIDENCE_INDEXES")) == list(
        evidence.evidence_index_statements()
    )


def test_native_identity_column_matches_the_python_upgrade() -> None:
    line = re.search(r"const EVIDENCE_IDENTITY_COLUMN: [^=]+= (.*);\n", SOURCE.read_text(encoding="utf-8"))
    assert line is not None
    assert line.group(1) == '[("action_identity", "text")]'
    assert "alter table guard_evidence add column action_identity text" in Path(evidence.__file__).read_text(
        encoding="utf-8"
    )
