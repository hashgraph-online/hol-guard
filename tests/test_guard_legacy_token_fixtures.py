"""Legacy Guard bearer-token fixture boundaries."""

from __future__ import annotations

from pathlib import Path


def test_guard_live_fixtures_are_rejection_only() -> None:
    legacy_prefix = "guard" + "_live" + "_"
    tests_root = Path(__file__).resolve().parent
    allowed_files = {
        "test_guard_oauth_device_connect.py",
        Path(__file__).name,
    }
    offenders = sorted(
        str(path.relative_to(tests_root))
        for path in tests_root.rglob("test_*.py")
        if path.name not in allowed_files and legacy_prefix in path.read_text(encoding="utf-8")
    )

    assert offenders == []
