"""The native Review outbox schema must match the statements Python runs.

The native runtime keeps its own copy of the outbox statements, the review
triggers and the upgrade step (``guard_store_schema_outbox*.rs``). This test
reads those files and requires the same text, versions and step order, so a
change to either side fails until the other follows.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from codex_plugin_scanner.guard import store_review_event_outbox_schema as outbox
from codex_plugin_scanner.guard import store_review_event_outbox_upgrade as upgrade

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "rust" / "crates" / "guard-runtime" / "src"
STEP = SOURCES / "guard_store_schema_outbox.rs"


def _raw_strings(name: str) -> list[str]:
    source = (SOURCES / name).read_text(encoding="utf-8")
    return re.findall(r'r##"(.*?)"##', source, re.S)


def _rust_const(name: str) -> str:
    source = STEP.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+=\s*(.*?);\n", source, re.S)
    assert match is not None, name
    return match.group(1)


def test_native_outbox_statements_match_python() -> None:
    assert _raw_strings("guard_store_schema_outbox_sql.rs") == list(outbox.review_event_outbox_schema_statements())


def test_native_review_triggers_match_python() -> None:
    insert_trigger = outbox._insert_trigger()  # pyright: ignore[reportPrivateUsage]
    update_trigger = outbox._update_trigger()  # pyright: ignore[reportPrivateUsage]
    assert _raw_strings("guard_store_schema_outbox_insert_sql.rs") == [insert_trigger]
    assert _raw_strings("guard_store_schema_outbox_update_sql.rs") == [update_trigger]


def test_native_versions_and_lists_match_python() -> None:
    assert int(_rust_const("OUTBOX_VERSION")) == outbox.REVIEW_EVENT_OUTBOX_MIGRATION_VERSION
    assert int(_rust_const("APPROVAL_INDEX_VERSION")) == 9
    columns: list[str] = re.findall(r'\("(\w+)", "text"\)', _rust_const("SEQUENCE_BINDING_COLUMNS"))
    upgrade_source = inspect.getsource(upgrade.ensure_review_event_outbox_upgrade)
    binding = re.search(r"binding_columns = \[(.*?)\]", upgrade_source, re.S)
    assert binding is not None
    assert columns == re.findall(r'"(\w+)"', binding.group(1))
    dropped: list[str] = re.findall(r'"(drop trigger[^"]*)"', _rust_const("DROPPED_TRIGGERS"))
    schema_source = inspect.getsource(outbox.ensure_review_event_outbox_schema)
    assert dropped == re.findall(r'"(drop trigger[^"]*)"', schema_source)


def test_native_steps_follow_the_python_order() -> None:
    source = STEP.read_text(encoding="utf-8")
    body = source[source.index("fn ensure_review_outbox") :]
    names = (
        '"approval_requests"',
        "OUTBOX_STATEMENTS",
        "upgrade(connection)",
        "migrate_retired_outbox",
        "DROPPED_TRIGGERS",
        "INSERT_TRIGGER",
        "UPDATE_TRIGGER",
        "OUTBOX_VERSION",
        "APPROVAL_INDEX_VERSION",
    )
    steps = re.findall("(" + "|".join(re.escape(name) for name in names) + ")", body[: body.index("\n}\n")])
    assert steps == list(names)
    schema_source = inspect.getsource(outbox.ensure_review_event_outbox_schema)
    python_order = [
        "alter table approval_requests add column oauth_source",
        "review_event_outbox_schema_statements()",
        "ensure_review_event_outbox_upgrade(",
        "_migrate_retired_outbox(connection, now)",
        "drop trigger if exists",
        "_insert_trigger()",
        "_update_trigger()",
        "REVIEW_EVENT_OUTBOX_MIGRATION_VERSION, now",
    ]
    positions = [schema_source.index(step) for step in python_order]
    assert positions == sorted(positions)
    opener = (ROOT / "src" / "codex_plugin_scanner" / "guard" / "store_connection_schema.py").read_text(
        encoding="utf-8"
    )
    after = opener.index("ensure_review_event_outbox_schema(connection")
    assert opener.index("self._record_schema_version(connection, version=9)", after) > after


def test_native_retired_outbox_migration_matches_python() -> None:
    retired = (SOURCES / "guard_store_schema_outbox_retired.rs").read_text(encoding="utf-8")
    key = re.search(r'const MIGRATED_KEY: &str = "([^"]+)";', retired)
    assert key is not None
    assert key.group(1) == outbox._RETIRED_OUTBOX_MIGRATION_STATE_KEY  # pyright: ignore[reportPrivateUsage]
    python_source = inspect.getsource(outbox._retired_outbox_payload) + inspect.getsource(  # pyright: ignore[reportPrivateUsage]
        outbox._migrate_retired_outbox  # pyright: ignore[reportPrivateUsage]
    )
    pattern = r'"(retired_[a-z_]+)"'
    native_reasons: list[str] = re.findall(pattern, retired)
    python_reasons: list[str] = re.findall(pattern, python_source)
    assert sorted(native_reasons) == sorted(python_reasons)
    marker = inspect.getsource(outbox._retired_outbox_marker_payload)  # pyright: ignore[reportPrivateUsage]
    keys: list[str] = re.findall(r'payload\.insert\(\s*"(\w+)"', retired)
    assert keys == re.findall(r'"(\w+)":', marker)
