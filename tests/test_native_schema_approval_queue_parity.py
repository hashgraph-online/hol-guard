"""The native approval-queue schema steps must match the ones Python runs.

The native runtime keeps its own copy of the Watch-only marking, its columns
and the order of the version 23, version 3 and approval-index steps
(``guard_store_schema_approvals.rs``). This test reads that file and requires
the same statements in the same order, so a change to either side fails until
the other follows.
"""

from __future__ import annotations

import inspect
import re
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_watch_only_approval_schema

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_approvals.rs"


def _rust_const(name: str) -> str:
    source = SOURCE.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+=\s*(.*?);\n", source, re.S)
    assert match is not None, name
    return match.group(1)


def test_native_watch_only_version_matches_python() -> None:
    assert (
        int(_rust_const("WATCH_ONLY_VERSION")) == store_watch_only_approval_schema.WATCH_ONLY_APPROVAL_MIGRATION_VERSION
    )


def test_native_watch_only_marking_matches_python() -> None:
    rust = re.fullmatch(r'r##"(.*)"##', _rust_const("MARK_WATCH_ONLY"), re.S)
    assert rust is not None
    python_source = inspect.getsource(store_watch_only_approval_schema.ensure_watch_only_approval_schema)
    python = re.search(r'"""(.*?)"""', python_source, re.S)
    assert python is not None
    assert rust.group(1) == textwrap.dedent(python.group(1)).strip()


def test_native_watch_only_columns_match_python() -> None:
    rust = re.findall(r'\("(\w+)", "([^"]+)"\)', _rust_const("WATCH_ONLY_COLUMNS"))
    python_source = inspect.getsource(store_watch_only_approval_schema.ensure_watch_only_approval_schema)
    text_columns = re.search(r"for column in \(([^)]*)\)", python_source)
    assert text_columns is not None
    names: list[str] = re.findall(r'"(\w+)"', text_columns.group(1))
    python = [(name, "text") for name in names]
    python.append(("watch_only_observation", "integer not null default 0"))
    assert rust == python


def test_native_steps_follow_the_python_order() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    body = source[source.index("fn ensure_approval_queue") :]
    names = ("WATCH_ONLY_COLUMNS", "MARK_WATCH_ONLY", "approval_backfill::backfill", "create_approval_indexes")
    steps = re.findall("(" + "|".join(re.escape(name) for name in names) + ")", body)
    assert steps == list(names)
    opener = (ROOT / "src" / "codex_plugin_scanner" / "guard" / "store_connection_schema.py").read_text(
        encoding="utf-8"
    )
    python_order = [
        'ensure_columns(connection, "approval_requests"',
        "ensure_watch_only_approval_schema(connection, schema=self)",
        "_backfill_approval_queue_columns_compat(connection)",
        "self._record_schema_version(connection, version=3)",
        "connection.execute(DROP_RETIRED_APPROVAL_GROUP_INDEX)",
        "approval_index_statements()",
    ]
    positions = [opener.index(step) for step in python_order]
    assert positions == sorted(positions)
