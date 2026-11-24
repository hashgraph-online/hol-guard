"""The native command activity schema must match the statements Python runs.

The native runtime keeps its own copy of the command activity and health
statements (``guard_store_schema_activity_sql.rs``) and their versions
(``guard_store_schema_activity.rs``). This test reads those files and requires
the same statements in the same order, so a change to either side fails until
the other follows.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_command_activity_health_schema as health
from codex_plugin_scanner.guard import store_command_activity_schema as activity

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
        for text in RAW_STRING.findall(_rust_block("guard_store_schema_activity_sql.rs", name))
    ]


def _python(statement: str) -> str:
    return textwrap.dedent(statement).strip()


def test_native_activity_statements_match_the_python_statements() -> None:
    assert _statements("ACTIVITY_STATEMENTS") == [
        _python(statement) for statement in activity.command_activity_schema_statements()
    ]


def test_native_health_statements_match_the_python_statements() -> None:
    pairs = {
        "HEALTH_TABLE": health._HEALTH_TABLE_SQL,
        "HEALTH_ACTIVE_TABLE": health._HEALTH_ACTIVE_TABLE_SQL,
        "HEALTH_SEED": health.HEALTH_SEED_SQL,
        "HEALTH_ACTIVE_SEED": health.HEALTH_ACTIVE_SEED_SQL,
    }
    for name, statement in pairs.items():
        assert _statements(name) == [_python(statement)], name


def test_native_activity_versions_match_the_python_versions() -> None:
    def version(name: str) -> str:
        return _rust_block("guard_store_schema_activity.rs", name).strip().strip('"')

    assert version("ACTIVITY_VERSION") == str(activity.COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION)
    assert version("HEALTH_VERSION") == str(health.COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION)
    assert version("HEALTH_ACTIVE_VERSION") == str(health.COMMAND_ACTIVITY_HEALTH_ACTIVE_MIGRATION_VERSION)
    assert version("HEALTH_SCHEMA_VERSION") == health.COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION
