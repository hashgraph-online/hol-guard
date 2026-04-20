from __future__ import annotations

from codex_plugin_scanner.guard.cli.render import emit_guard_payload


def test_guard_connect_render_clarifies_paid_plan_pending_state(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "first_sync_pending",
            "reason": "Guard Cloud sync requires a paid Guard plan",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Browser paired" in output
    assert "Connection" in output
    assert "This device is protected locally" in output
    assert "Upgrade to sync this device to Guard Cloud" in output


def test_guard_connect_render_defaults_sync_not_available_to_upgrade_guidance(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "sync_not_available",
            "reason": "Sync is not available right now.",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
        False,
    )

    output = capsys.readouterr().out
    assert "This device is protected locally" in output
    assert "Upgrade to sync this device to Guard Cloud" in output
    assert "First Guard Cloud proof is on the way" not in output


def test_guard_connect_render_tolerates_non_numeric_sync_counts(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "sync": {
                "receipts_stored": "pending",
                "inventory_tracked": "unknown",
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Receipts stored" in output
    assert "Inventory tracked" in output
    assert "0" in output


def test_guard_connect_render_tolerates_non_finite_sync_counts(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "sync": {
                "receipts_stored": float("nan"),
                "inventory_tracked": float("inf"),
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Receipts stored" in output
    assert "Inventory tracked" in output
    assert "0" in output


def test_guard_connect_render_clarifies_browser_approval_wait(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": False,
            "browser_opened": True,
            "status": "waiting",
            "milestone": "waiting_for_browser",
            "completed_at": None,
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Browser paired" in output
    assert "Browser approval pending" in output
    assert "Waiting for browser approval" in output
