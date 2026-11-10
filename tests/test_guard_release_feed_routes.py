"""The dashboard's Releases tab is one of its pages."""

from __future__ import annotations

from codex_plugin_scanner.guard.routes import request_handler as daemon_server_module


def test_every_dashboard_page_is_served_as_the_dashboard() -> None:
    # Opening or reloading any dashboard page, the Releases tab included,
    # serves the dashboard rather than 404.
    for route in (
        "/",
        "/home",
        "/dashboard",
        "/inbox",
        "/requests",
        "/requests/r1",
        "/approvals",
        "/approvals/a1",
        "/protect",
        "/apps/slack",
        "/evidence",
        "/extensions",
        "/extensions/command.git",
        "/supply-chain",
        "/audit",
        "/policy",
        "/feed-health",
        "/workspaces",
        "/protection/repair",
        "/releases",
        "/settings",
    ):
        assert daemon_server_module._GuardDaemonHandler._is_dashboard_route(route), route
