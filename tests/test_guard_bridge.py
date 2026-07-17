"""Security tests for Guard Bridge daemon integration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import bridge as guard_bridge_module
from codex_plugin_scanner.guard.bridge import BridgeConfig, GuardBridge, PendingRequest, WebhookBackend
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore


def _build_pending_request() -> PendingRequest:
    return PendingRequest(
        request_id="req-bridge",
        artifact_id="artifact-123",
        artifact_name=".env",
        artifact_type="file",
        policy_action="block",
        harness="codex",
        source_scope="project",
        risk_summary={"overall_risk_level": "high"},
        created_at="2026-06-05T00:00:00+00:00",
    )


def test_guard_bridge_fetch_pending_requests_sends_guard_token_header(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    token_path = store.guard_home / "daemon-auth-token"
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text("bridge-token", encoding="utf-8")
    token_path.chmod(0o600)
    bridge = GuardBridge(
        config=BridgeConfig(guard_url="http://127.0.0.1:4455", dry_run=False),
        store=store,
    )
    get_calls: list[tuple[str, dict[str, str], int]] = []

    def fake_get(url: str, *, headers: dict[str, str], timeout: int):
        get_calls.append((url, headers, timeout))
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "items": [
                    {
                        "request_id": "req-bridge",
                        "artifact_id": "artifact-123",
                        "artifact_name": ".env",
                        "artifact_type": "file",
                        "policy_action": "block",
                        "harness": "codex",
                        "source_scope": "project",
                        "risk_summary": {"overall_risk_level": "high"},
                        "created_at": "2026-06-05T00:00:00+00:00",
                    }
                ]
            },
        )

    monkeypatch.setattr(guard_bridge_module.requests, "get", fake_get)

    requests_list = bridge._fetch_pending_requests("http://127.0.0.1:4455")

    assert [request.request_id for request in requests_list] == ["req-bridge"]
    assert get_calls == [
        (
            "http://127.0.0.1:4455/v1/requests",
            {"X-Guard-Token": "bridge-token"},
            10,
        )
    ]


def test_guard_bridge_fetch_pending_requests_fails_closed_without_daemon_token(tmp_path, monkeypatch, capsys):
    store = GuardStore(tmp_path / "guard-home")
    bridge = GuardBridge(
        config=BridgeConfig(guard_url="http://127.0.0.1:4455", dry_run=False),
        store=store,
    )
    called = False

    def fake_get(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("requests.get should not run without daemon auth token")

    monkeypatch.setattr(guard_bridge_module.requests, "get", fake_get)

    requests_list = bridge._fetch_pending_requests("http://127.0.0.1:4455")

    assert requests_list == []
    assert called is False
    assert "No daemon auth token found" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("scheme", "host", "path"),
    [
        ("http", "hooks.example.test", "/guard"),
        ("https", "127.0.0.1", "/guard"),
        ("https", "[0:0:0:0:0:0:0:1]", "/guard"),
        ("https", "[::ffff:127.0.0.1]", "/guard"),
        ("https", "169.254.169.254", "/guard"),
    ],
)
def test_webhook_backend_rejects_unsafe_urls(scheme: str, host: str, path: str):
    url = f"{scheme}:{'//'}{host}{path}"
    with pytest.raises(ValueError):
        WebhookBackend(url)


def test_webhook_backend_redacts_artifact_details_by_default(monkeypatch):
    backend = WebhookBackend("https://hooks.example.test/guard")
    request = _build_pending_request()
    post_calls: list[tuple[str, dict[str, object], int]] = []

    def fake_post(url: str, *, json: dict[str, object], timeout: int):
        post_calls.append((url, json, timeout))
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(guard_bridge_module.requests, "post", fake_post)

    sent = backend.send_notification(request, "raw notification with artifact details")

    assert sent is True
    assert post_calls == [
        (
            "https://hooks.example.test/guard",
            {
                "text": "HOL Guard approval pending. Review locally to see artifact details.",
                "request_id": "req-bridge",
            },
            10,
        )
    ]


def test_guard_bridge_cli_can_opt_into_artifact_details(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    class _FakeGuardBridge:
        def __init__(self, *, config, store, backend):
            captured["backend"] = backend

        def run(self) -> None:
            return

    monkeypatch.setattr(guard_commands_module, "GuardBridge", _FakeGuardBridge)

    rc = main(
        [
            "guard",
            "bridge",
            "--home",
            str(tmp_path / "guard-home"),
            "--webhook-url",
            "https://hooks.example.test/guard",
            "--webhook-include-artifact-details",
            "--dry-run",
        ]
    )

    assert rc == 0
    assert isinstance(captured["backend"], WebhookBackend)
    assert captured["backend"].include_artifact_details is True
