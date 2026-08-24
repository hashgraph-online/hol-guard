"""Legacy Guard bearer-token fixture boundaries."""

from __future__ import annotations

import re
from pathlib import Path


def test_guard_live_fixtures_are_rejection_only() -> None:
    legacy_prefix = "guard" + "_live" + "_"
    legacy_bearer = re.compile(rf"{legacy_prefix}[A-Za-z0-9_-]+")
    schema_reference = re.compile(
        rf"(?:create\s+(?:table|trigger)|insert\s+into)\s+{legacy_prefix}request_outbox"
        + rf"(?:_after_(?:insert|update))?\b|name\s+like\s+['\"]{legacy_prefix}request_outbox_%['\"]",
        re.IGNORECASE,
    )

    def contains_legacy_bearer(value: str) -> bool:
        return legacy_bearer.search(schema_reference.sub("", value)) is not None

    assert contains_legacy_bearer(f'"{legacy_prefix}secret"')
    assert contains_legacy_bearer(f"Authorization: Bearer {legacy_prefix}secret")
    assert contains_legacy_bearer(f"Bearer {legacy_prefix}request_outbox_secret")
    assert not contains_legacy_bearer(f"create table {legacy_prefix}request_outbox")
    assert not contains_legacy_bearer(f"create trigger {legacy_prefix}request_outbox_after_insert")
    assert not contains_legacy_bearer(f"name like '{legacy_prefix}request_outbox_%'")
    tests_root = Path(__file__).resolve().parent
    allowed_files = {
        "test_guard_oauth_device_connect.py",
        Path(__file__).name,
    }
    offenders = sorted(
        str(path.relative_to(tests_root))
        for path in tests_root.rglob("test_*.py")
        if str(path.relative_to(tests_root)) not in allowed_files
        and contains_legacy_bearer(path.read_text(encoding="utf-8"))
    )

    assert offenders == []
