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
    assert "Guard status" in output
    assert "Machine registered" in output
    assert "Shared proof sync needs a paid Guard plan" in output


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
