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


def test_guard_status_render_rewrites_internal_next_action_labels(capsys) -> None:
    emit_guard_payload(
        "status",
        {
            "managed_harnesses": 1,
            "receipt_count": 3,
            "pending_approvals": 1,
            "sync_configured": False,
            "cloud_state": "local_only",
            "cloud_state_label": "Local only",
            "cloud_state_detail": "Guard is protecting this machine locally.",
            "dashboard_url": "https://hol.org/guard",
            "connect_url": "https://hol.org/guard/connect",
            "advisory_count": 0,
            "harnesses": [
                {
                    "harness": "codex",
                    "managed": False,
                    "artifact_count": 2,
                    "review_count": 0,
                    "next_action": "install",
                },
                {
                    "harness": "claude-code",
                    "managed": True,
                    "artifact_count": 4,
                    "review_count": 2,
                    "next_action": "review",
                },
                {
                    "harness": "copilot",
                    "managed": True,
                    "artifact_count": 1,
                    "review_count": 0,
                    "next_action": "run",
                },
                {
                    "harness": "cursor",
                    "managed": False,
                    "artifact_count": 0,
                    "review_count": 0,
                    "next_action": "install-harness",
                },
            ],
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Recommended action" in output
    assert "Install Guard" in output
    assert "Review 2 changes" in output
    assert "Run through Guard" in output
    assert "Install harness first" in output


def test_guard_bootstrap_render_rewrites_skip_reason_labels(capsys) -> None:
    emit_guard_payload(
        "bootstrap",
        {
            "recommended_harness": "codex",
            "approval_center_url": "http://127.0.0.1:4781",
            "approval_center_reachable": True,
            "bootstrap_install": {
                "installed": False,
                "harness": "codex",
                "reason": "skipped_by_flag",
            },
            "shell_alias": {
                "snippet": "alias guardp='hol-guard protect'",
            },
            "next_steps": [],
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Install skipped for now" in output
    assert "skipped_by_flag" not in output


def test_guard_bootstrap_render_rewrites_missing_harness_reason(capsys) -> None:
    emit_guard_payload(
        "bootstrap",
        {
            "recommended_harness": None,
            "approval_center_url": "http://127.0.0.1:4781",
            "approval_center_reachable": True,
            "bootstrap_install": {
                "installed": False,
                "reason": "no_harness_detected",
            },
            "next_steps": [],
        },
        False,
    )

    output = capsys.readouterr().out
    assert "No supported harness detected yet" in output
    assert "no_harness_detected" not in output
