"""The native workspace assessment schema must match the statements Python runs.

``guard_store_schema_workspace_sql.rs`` keeps its own copy of the workspace
assessment and fix proposal statements. These tests require each native
statement to equal its Python statement, in order, and the recorded versions
to agree, so a change to either side fails until the other follows.
"""

from __future__ import annotations

import re
from pathlib import Path

from codex_plugin_scanner.guard import store_workspace_assessment_schema as schema

SQL = (
    Path(__file__).resolve().parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "src"
    / "guard_store_schema_workspace_sql.rs"
)


def _normal(text: str) -> str:
    return " ".join(text.split())


def _rust_statements(name: str) -> list[str]:
    source = SQL.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: \[&str; \d+\] = \[(.*?)\n\];", source, re.S)
    assert match is not None, name
    return re.findall(r'r##"(.*?)"##', match.group(1), re.S)


def _rust_version(name: str) -> int:
    match = re.search(rf"const {name}: i64 = (\d+);", SQL.read_text(encoding="utf-8"))
    assert match is not None, name
    return int(match.group(1))


def test_native_assessment_statements_match_python() -> None:
    native = [_normal(statement) for statement in _rust_statements("ASSESSMENT_STATEMENTS")]
    assert native == [_normal(statement) for statement in schema._STATEMENTS]  # pyright: ignore[reportPrivateUsage]


def test_native_fix_proposal_statements_match_python() -> None:
    native = [_normal(statement) for statement in _rust_statements("FIX_PROPOSAL_STATEMENTS")]
    python = schema._FIX_PROPOSAL_STATEMENTS  # pyright: ignore[reportPrivateUsage]
    assert native == [_normal(statement) for statement in python]


def test_native_versions_match_python() -> None:
    assert _rust_version("ASSESSMENT_VERSION") == schema.WORKSPACE_ASSESSMENT_MIGRATION_VERSION
    assert _rust_version("FIX_PROPOSAL_VERSION") == schema.WORKSPACE_FIX_PROPOSAL_MIGRATION_VERSION
