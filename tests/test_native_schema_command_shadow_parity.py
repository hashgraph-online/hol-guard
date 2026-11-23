"""The native command shadow schema must match the statements Python runs.

``guard_store_schema_shadow_sql.rs`` keeps its own copy of the current,
version 17, initial version 18 and version 15 command shadow statements. The
native step recognizes a historical store by comparing its objects with these
copies, so a change to either side must fail here until the other follows.
"""

from __future__ import annotations

import re
from pathlib import Path

from codex_plugin_scanner.guard import store_command_shadow_schema as schema
from codex_plugin_scanner.guard.store_command_shadow_schema_v18 import INITIAL_V18_SCHEMA_STATEMENTS

SQL = (
    Path(__file__).resolve().parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "src"
    / "guard_store_schema_shadow_sql.rs"
)


def _normal(text: str) -> str:
    return " ".join(text.split())


def _canonical(text: str) -> str:
    return " ".join(text.strip().lower().split())


def _source() -> str:
    return SQL.read_text(encoding="utf-8")


def _rust_statements(name: str) -> list[str]:
    match = re.search(rf"const {name}: \[&str; (\d+)\] = \[(.*?)\n\];", _source(), re.S)
    assert match is not None, name
    statements = re.findall(r'r##"(.*?)"##', match.group(2), re.S)
    # Every element must be a parsed literal: a statement in another literal
    # form would run natively while escaping the comparison below.
    assert len(statements) == int(match.group(1)), name
    return statements


def _rust_statement(name: str) -> str:
    match = re.search(rf'const {name}: &str = r##"(.*?)"##;', _source(), re.S)
    assert match is not None, name
    return match.group(1)


def test_native_current_statements_match_python() -> None:
    native = [_normal(statement) for statement in _rust_statements("CURRENT")]
    python = schema._SCHEMA_STATEMENTS  # pyright: ignore[reportPrivateUsage]
    assert native == [_normal(statement) for statement in python]


def test_native_legacy_statements_match_python() -> None:
    native = [_normal(statement) for statement in _rust_statements("LEGACY")]
    python = schema._LEGACY_SCHEMA_STATEMENTS  # pyright: ignore[reportPrivateUsage]
    assert native == [_normal(statement) for statement in python]


def test_native_previous_profile_matches_python() -> None:
    current = schema._SCHEMA_STATEMENTS  # pyright: ignore[reportPrivateUsage]
    previous = schema._PREVIOUS_SCHEMA_STATEMENTS  # pyright: ignore[reportPrivateUsage]
    native = [_rust_statement("PREVIOUS_EVALUATIONS"), *current[1:]]
    assert [_normal(statement) for statement in native] == [_normal(statement) for statement in previous]


def test_native_initial_v18_profile_matches_python() -> None:
    current = schema._SCHEMA_STATEMENTS  # pyright: ignore[reportPrivateUsage]
    native = [_rust_statement("INITIAL_V18_EVALUATIONS"), *current[1:]]
    python = INITIAL_V18_SCHEMA_STATEMENTS
    assert [_canonical(statement) for statement in native] == [_canonical(statement) for statement in python]


def test_native_versions_match_python() -> None:
    match = re.search(r"const VERSIONS: \[i64; 3\] = \[(\d+), (\d+), (\d+)\];", _source())
    assert match is not None
    assert tuple(int(value) for value in match.groups()) == (
        schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,
        schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,
        schema.COMMAND_SHADOW_MIGRATION_VERSION,
    )
    current = re.search(r"const CURRENT_VERSION: i64 = (\d+);", _source())
    assert current is not None
    assert int(current.group(1)) == schema.COMMAND_SHADOW_MIGRATION_VERSION
