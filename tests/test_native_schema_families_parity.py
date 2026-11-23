"""The native schema families must match the steps the Python store runs.

The native runtime keeps its own copy of the resume schema lists, the receipt
command-binding column and the Bash journal versions
(``guard_store_schema_families.rs``). This test reads that file and requires
the same entries, so a change to either side fails until the other follows.
"""

from __future__ import annotations

import re
import sqlite3
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_bash_operation_schema as bash
from codex_plugin_scanner.guard import store_native_decision_receipts as receipts
from codex_plugin_scanner.guard import store_resume as resume

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_families.rs"
PAIR = re.compile(r'\("([^"]+)",\s*"([^"]+)"\)')
RAW_STRING = re.compile(r'r##"(.*?)"##', re.S)


def _rust_block(name: str) -> str:
    source = RUST.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+=\s*(.*?);\n", source, re.S)
    assert match is not None, name
    return match.group(1)


def test_native_resume_lists_match_the_python_lists() -> None:
    for name in ("RESUME_CONTINUATION_COLUMNS", "CONTINUATION_CLAIM_COLUMNS"):
        assert PAIR.findall(_rust_block(name)) == [tuple(pair) for pair in getattr(resume, name)], name
    for name in ("CONTINUATION_CLAIMS_TABLE", "CONTINUATION_EFFECTS_TABLE"):
        assert RAW_STRING.findall(_rust_block(name)) == [textwrap.dedent(getattr(resume, name)).strip()], name


def test_native_receipt_binding_column_matches_the_python_column() -> None:
    block = _rust_block("COMMAND_BINDING_COLUMN")
    native = " ".join("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block, re.S)).replace("\\\n", " ").split())
    assert native == " ".join(receipts._COMMAND_BINDING_COLUMN.split())
    version = receipts.NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION
    assert _rust_block("COMMAND_BINDING_VERSION").strip() == str(version)


def test_native_bash_versions_match_the_python_versions() -> None:
    native = [int(value) for value in re.findall(r"\d+", _rust_block("BASH_VERSIONS"))]
    assert native == [
        bash.BASH_OPERATION_MIGRATION_VERSION,
        bash.BASH_REVIEW_MIGRATION_VERSION,
        bash.BASH_INVOCATION_MIGRATION_VERSION,
    ]


def test_resume_schema_upgrades_a_legacy_table_once() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("create table guard_request_resumes (request_id text primary key)")
        resume.ensure_resume_schema(connection)
        resume.ensure_resume_schema(connection)
        names = [str(row[1]) for row in connection.execute("pragma table_info(guard_request_resumes)")]
        tables = {str(row[0]) for row in connection.execute("select name from sqlite_master where type = 'table'")}
    finally:
        connection.close()
    assert names == ["request_id"] + [name for name, _ in resume.RESUME_CONTINUATION_COLUMNS]
    assert {"guard_continuation_claims", "guard_continuation_effects"} <= tables
