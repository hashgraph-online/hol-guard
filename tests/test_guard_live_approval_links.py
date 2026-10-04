"""Live approval links stay authenticated, local, and out of JSON output."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard.approval_hook_copy import is_loopback_approval_url
from codex_plugin_scanner.guard.cli import commands_support_interaction, render
from codex_plugin_scanner.guard.cli.commands_support_interaction import _open_codex_live_approval
from codex_plugin_scanner.guard.cli.render import emit_guard_payload


def _write_daemon_token(guard_home: Path, token: str) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text(token, encoding="utf-8")
    token_path.chmod(0o600)


def _approval_payload(url: str, request_id: str = "req-live") -> dict[str, object]:
    return {
        "approval_requests": [{"request_id": request_id, "approval_url": url}],
        "primary_approval_url": url,
    }


def test_codex_live_wait_prints_and_opens_signed_loopback_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_daemon_token(guard_home, "private-daemon-token")
    review_url = "http://127.0.0.1:5475/requests/req-live"
    opened_urls: list[str] = []
    monkeypatch.setattr(
        commands_support_interaction,
        "open_browser_url",
        lambda url: opened_urls.append(url) or True,
    )

    _open_codex_live_approval(_approval_payload(review_url), guard_home=guard_home)

    captured = capsys.readouterr()
    assert len(opened_urls) == 1
    signed_url = opened_urls[0]
    assert signed_url.startswith(review_url + "#guard-token=")
    assert parse_qs(urlparse(signed_url).fragment)["guard-token"][0].startswith("gld1.")
    assert signed_url in captured.err
    assert "private-daemon-token" not in captured.err


def test_codex_live_wait_without_token_prints_recovery_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    review_url = "http://127.0.0.1:5475/requests/req-live"
    opened_urls: list[str] = []
    monkeypatch.setattr(
        commands_support_interaction,
        "open_browser_url",
        lambda url: opened_urls.append(url) or True,
    )

    _open_codex_live_approval(_approval_payload(review_url), guard_home=guard_home)

    captured = capsys.readouterr()
    assert opened_urls == []
    assert "hol-guard approvals open req-live" in captured.err
    assert review_url not in captured.err
    assert "guard-token" not in captured.err


def test_codex_live_wait_never_opens_or_signs_external_url(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_daemon_token(guard_home, "private-daemon-token")
    review_url = "https://example.invalid/requests/req-external"
    opened_urls: list[str] = []
    monkeypatch.setattr(
        commands_support_interaction,
        "open_browser_url",
        lambda url: opened_urls.append(url) or True,
    )

    _open_codex_live_approval(_approval_payload(review_url, "req-external"), guard_home=guard_home)

    captured = capsys.readouterr()
    assert opened_urls == []
    assert "hol-guard approvals open req-external" in captured.err
    assert review_url not in captured.err
    assert "guard-token" not in captured.err


def test_manual_approval_render_without_token_uses_recovery_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    review_url = "http://127.0.0.1:5475/requests/req-render"
    monkeypatch.setattr(render, "_RICH_AVAILABLE", False)

    emit_guard_payload(
        "approvals",
        {"request_id": "req-render", "approval_url": review_url},
        False,
        live_approval_home=guard_home,
    )

    output = capsys.readouterr().out
    assert "hol-guard approvals open req-render" in output
    assert review_url not in output
    assert "guard-token" not in output


def test_approval_json_does_not_gain_live_session_token(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    _write_daemon_token(guard_home, "private-daemon-token")
    review_url = "http://127.0.0.1:5475/requests/req-json"
    payload = {"request_id": "req-json", "approval_url": review_url}

    emit_guard_payload("approvals", payload, True, live_approval_home=guard_home)

    output = capsys.readouterr().out
    assert "guard-token" not in output
    assert json.loads(output)["approval_url"] == review_url


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@127.0.0.1:5475/requests/req-userinfo",
        "http://127.0.0.1:not-a-port/requests/req-port",
        "https://example.invalid/requests/req-external",
    ],
)
def test_loopback_approval_validation_rejects_unsafe_authorities(url: str) -> None:
    assert not is_loopback_approval_url(url)
