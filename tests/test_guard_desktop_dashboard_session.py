from __future__ import annotations

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
