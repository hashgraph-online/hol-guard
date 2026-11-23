"""The native versioned schema steps must match the Python statements.

``guard_store_schema_versions.rs`` keeps a copy of each statement in
``store_schema_versions.py`` and of the rollup rebuild request. This test reads
that file and requires each constant to equal its Python counterpart, and
checks that the Python steps run once.
"""

from __future__ import annotations

import inspect
import re
import sqlite3
import textwrap
from pathlib import Path

from codex_plugin_scanner.guard import store_receipt_rollup_schema
from codex_plugin_scanner.guard import store_schema_versions as versions

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_versions.rs"
RAW_STRING = re.compile(r'r##"(.*?)"##', re.S)
PLAIN_STRING = re.compile(r'"([^"]*)"')
SINGLE = (
    "RECORD_SCHEMA_VERSION",
    "SCHEMA_VERSION_APPLIED",
    "RECEIPT_ENVELOPES_TABLE",
    "DROP_RETIRED_APPROVAL_GROUP_INDEX",
    "LOCAL_DEVICE_SELECT",
    "LOCAL_DEVICE_INSERT",
    "REOPEN_EXPIRED_APPROVALS",
)


def _rust_value(name: str) -> str:
    source = RUST.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+=\s*(.*?);\n", source, re.S)
    assert match is not None, name
    return match.group(1)


def _clean(statement: str) -> str:
    return textwrap.dedent(statement).strip()


def test_native_statements_match_the_python_constants() -> None:
    for name in SINGLE:
        assert RAW_STRING.findall(_rust_value(name)) == [_clean(getattr(versions, name))], name
    steps = RAW_STRING.findall(_rust_value("V5_RECEIPT_ENVELOPE_STEPS"))
    assert steps == [_clean(step) for step in versions.V5_RECEIPT_ENVELOPE_STEPS]


def test_native_names_match_the_python_names() -> None:
    assert PLAIN_STRING.findall(_rust_value("LOCAL_DEVICE_KEY")) == ["local-device"]
    assert PLAIN_STRING.findall(_rust_value("LOCAL_DEVICE_LABEL")) == [versions.LOCAL_DEVICE_LABEL]
    assert PLAIN_STRING.findall(_rust_value("ROLLUP_REBUILD_PENDING_KEY")) == [
        store_receipt_rollup_schema.RECEIPT_ROLLUP_REBUILD_PENDING_KEY
    ]


def test_native_rollup_rebuild_matches_the_python_request() -> None:
    source = inspect.getsource(store_receipt_rollup_schema.request_receipt_rollup_rebuild)
    match = re.search(r'"""\n(\s+insert into sync_state.*?)"""', source, re.S)
    assert match is not None
    assert RAW_STRING.findall(_rust_value("REQUEST_ROLLUP_REBUILD")) == [_clean(match.group(1))]


def test_the_local_device_is_inserted_once() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            "create table guard_devices (device_key text primary key, installation_id text, "
            "device_label text, created_at text, updated_at text)"
        )
        versions.ensure_local_device(connection, installation_id="first", now="t1")
        versions.ensure_local_device(connection, installation_id="second", now="t2")
        rows = connection.execute("select installation_id, device_label, created_at from guard_devices").fetchall()
    finally:
        connection.close()
    assert rows == [("first", "Local machine", "t1")]
