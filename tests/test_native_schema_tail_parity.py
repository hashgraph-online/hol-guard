"""The native schema tail must run the steps Python runs after the outbox.

``guard_store_schema_tail.rs`` mirrors the end of the Python schema opener:
receipt rollups, rollup rebuild requests, the marker versions, attachment
columns, the local device, storage maintenance, version 2 and the expired
approval reopen. This test reads both sides and requires the same versions
and step order, so a change to either side fails until the other follows.
"""

from __future__ import annotations

import re
from pathlib import Path

from codex_plugin_scanner.guard import store_connection_schema as opener
from codex_plugin_scanner.guard.store_storage_maintenance import (
    STORAGE_MAINTENANCE_MIGRATION_VERSION,
    STORAGE_QUERY_INDEX_MIGRATION_VERSION,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "rust" / "crates" / "guard-runtime" / "src"
TAIL = SOURCES / "guard_store_schema_tail.rs"


def _rust_list(name: str) -> list[int]:
    source = TAIL.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: \[i64; \d+\] = \[([^\]]*)\];", source)
    assert match is not None, name
    values: list[str] = re.findall(r"\d+", match.group(1))
    return [int(value) for value in values]


def _python_tail() -> str:
    source = Path(opener.__file__).read_text(encoding="utf-8")
    start = source.index("ensure_review_event_outbox_schema(connection")
    return source[start : source.index("connection.execute(REOPEN_EXPIRED_APPROVALS)", start) + 50]


def _rust_tail() -> str:
    source = TAIL.read_text(encoding="utf-8")
    body = source[source.index("fn ensure_tail") :]
    return body[: body.index("\n}\n")]


def test_native_tail_versions_match_python() -> None:
    tail = _python_tail()
    assert _rust_list("MARKER_VERSIONS") == [7, 8]
    for version in _rust_list("MARKER_VERSIONS"):
        assert f"self._record_schema_version(connection, version={version})" in tail
    assert _rust_list("STORAGE_VERSIONS") == [
        STORAGE_MAINTENANCE_MIGRATION_VERSION,
        STORAGE_QUERY_INDEX_MIGRATION_VERSION,
    ]
    base = re.search(r"const BASE_VERSION: i64 = (\d+);", TAIL.read_text(encoding="utf-8"))
    assert base is not None
    assert f"self._record_schema_version(connection, version={base.group(1)})" in tail
    assert opener._RECEIPT_WARN_ROLLUP_MIGRATION_VERSION == 16  # pyright: ignore[reportPrivateUsage]
    rebuilds = (SOURCES / "guard_store_schema.rs").read_text(encoding="utf-8")
    assert "for version in [6, 16] {" in rebuilds


def test_native_tail_follows_the_python_order() -> None:
    native_steps = (
        "create_receipt_rollups",
        "request_rollup_rebuilds",
        "MARKER_VERSIONS",
        "upgrade_client_attachments",
        "ensure_local_device",
        "create_storage_maintenance",
        "STORAGE_VERSIONS",
        "BASE_VERSION",
        "reopen_expired_approvals",
    )
    body = _rust_tail()
    found: list[str] = re.findall("(" + "|".join(native_steps) + ")", body)
    assert found == list(native_steps)
    python_steps = (
        "receipt_index_statements()",
        "request_receipt_rollup_rebuild(",
        "version=7)",
        '"guard_client_attachments", ATTACHMENT_COLUMNS',
        "self._ensure_local_device(connection)",
        "storage_maintenance_schema_statements()",
        "version=STORAGE_MAINTENANCE_MIGRATION_VERSION",
        "version=2)",
        "REOPEN_EXPIRED_APPROVALS",
    )
    tail = _python_tail()
    positions = [tail.index(step) for step in python_steps]
    assert positions == sorted(positions)
