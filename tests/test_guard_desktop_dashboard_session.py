from __future__ import annotations

import argparse
import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from codex_plugin_scanner.guard import dashboard_launcher
from codex_plugin_scanner.guard.cli import commands_dispatch_desktop


def test_desktop_dashboard_session_is_scoped_fragment_token(monkeypatch) -> None:
    raw_daemon_token = "daemon-secret-that-must-not-cross-the-desktop-boundary"
    monkeypatch.setattr(
        dashboard_launcher,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:43123/",
    )
    monkeypatch.setattr(
        dashboard_launcher,
        "load_guard_daemon_auth_token",
        lambda _guard_home: raw_daemon_token,
    )

    url = dashboard_launcher.build_desktop_dashboard_session_url(guard_home=__import__("pathlib").Path("/tmp/guard"))
    parsed = urlparse(url)
    fragment = parse_qs(parsed.fragment)

    assert parsed.scheme == "http"
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port == 43123
    assert parse_qs(parsed.query) == {dashboard_launcher.DESKTOP_DASHBOARD_EMBED_QUERY_KEY: ["1"]}
    assert set(fragment) == {"guard-token"}
    assert fragment["guard-token"][0].startswith("gld1.")
    assert raw_daemon_token not in url


def test_desktop_bootstrap_uses_canonical_dashboard_session_builder() -> None:
    source = __import__("inspect").getsource(commands_dispatch_desktop._run_guard_desktop_command)
    assert "build_desktop_dashboard_session_url" in source
    assert 'dashboard["sessionUrl"]' in source
    assert 'dashboard["canonical"] = True' in source
    assert source.index("session_url = build_desktop_dashboard_session_url") < source.index(
        "build_guard_status_payload"
    )


def test_desktop_bootstrap_aligns_runtime_before_projecting_protection(monkeypatch, tmp_path: Path) -> None:
    runtime_ready = {"value": False}
    call_order: list[str] = []

    def fake_session_url(*, guard_home: Path) -> str:
        del guard_home
        call_order.append("session")
        runtime_ready["value"] = True
        return "http://127.0.0.1:43123/?desktop_embed=1#guard-token=gld1.test"

    def fake_status(_context: object, _store: object, _config: object) -> dict[str, object]:
        call_order.append("status")
        return {
            "runtime_status": "active" if runtime_ready["value"] else "offline",
            "managed_harnesses": 1,
            "receipt_count": 0,
            "pending_approvals": 0,
            "cloud_state": "local_only",
            "last_sync_at": None,
            "harnesses": [
                {
                    "harness": "codex",
                    "installed": True,
                    "command_available": True,
                    "artifact_count": 1,
                    "review_count": 0,
                    "warning_count": 0,
                    "managed": True,
                }
            ],
        }

    monkeypatch.setattr(commands_dispatch_desktop, "build_desktop_dashboard_session_url", fake_session_url)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.product.build_guard_status_payload",
        fake_status,
    )

    output = StringIO()
    result = commands_dispatch_desktop._run_guard_desktop_command(
        argparse.Namespace(desktop_command="bootstrap"),
        guard_home=tmp_path,
        context=SimpleNamespace(guard_home=tmp_path),
        store=SimpleNamespace(
            list_approval_requests=lambda **_kwargs: [],
            oldest_approval_request_created_at=lambda **_kwargs: None,
            count_approval_requests=lambda **_kwargs: 0,
            list_receipts=lambda **_kwargs: [],
            receipt_summary_between=lambda **_kwargs: {
                "blocked": 0,
                "approved": 0,
                "latest_at": None,
            },
        ),
        config=SimpleNamespace(),
        output_stream=output,
    )

    payload = json.loads(output.getvalue())
    assert result == 0
    assert call_order == ["session", "status"]
    assert payload["status"] == "ready"
    assert payload["protection"]["state"] == "protected"
    assert payload["apps"][0]["protection"] == "protected"
    assert payload["daemon"] == {"running": True}
    assert payload["dashboard"]["sessionUrl"].startswith("http://127.0.0.1:43123/")
