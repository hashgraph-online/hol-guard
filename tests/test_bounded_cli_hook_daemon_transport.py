from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon


@pytest.mark.parametrize("url", ["https://127.0.0.1:4781/hook", "http://example.com/hook"])
def test_loopback_url_rejects_wrong_scheme_and_remote_host(url: str) -> None:
    with pytest.raises(ValueError):
        daemon._assert_loopback_http_url(url)


def test_loopback_opener_disables_proxies_and_installs_redirect_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: list[object] = []
    sentinel = cast(urllib.request.OpenerDirector, object())

    def build(*items: object) -> urllib.request.OpenerDirector:
        handlers.extend(items)
        return sentinel

    monkeypatch.setattr(daemon.urllib.request, "build_opener", build)

    assert daemon._build_loopback_opener() is sentinel
    proxy = next(item for item in handlers if isinstance(item, urllib.request.ProxyHandler))
    assert proxy.proxies == {}
    assert any(isinstance(item, daemon._LoopbackOnlyRedirectHandler) for item in handlers)


def test_redirect_guard_rejects_remote_target_before_following() -> None:
    handler = daemon._LoopbackOnlyRedirectHandler()
    request = urllib.request.Request("http://127.0.0.1:4781/start")

    with pytest.raises(ValueError, match="loopback"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/escape")

    redirected = handler.redirect_request(request, None, 302, "Found", {}, "http://localhost:4781/next")
    assert redirected is not None
    assert redirected.full_url == "http://localhost:4781/next"


@pytest.mark.parametrize("stored, expected", [("secret", "secret"), ("", None), (None, None)])
def test_daemon_auth_token_preserves_only_nonempty_private_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stored: str | None,
    expected: str | None,
) -> None:
    seen: dict[str, object] = {}

    def read(path: Path, **kwargs: object) -> str | None:
        seen.update(path=path, **kwargs)
        return stored

    monkeypatch.setattr(daemon, "read_private_regular_text", read)
    guard_home = tmp_path / "guard-home"

    assert daemon._read_daemon_auth_token(guard_home) == expected
    assert seen == {
        "path": guard_home / "daemon-auth-token",
        "max_bytes": 4096,
        "require_private_parent": True,
    }


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (None, None),
        ("not-json", None),
        ("[]", None),
        ('{"host":1,"port":4781}', None),
        ('{"host":"example.com","port":4781}', None),
        ('{"host":"::2","port":4781}', None),
        ('{"host":"[::1]","port":4781}', None),
        ('{"host":"127.0.0.1","port":"4781"}', None),
        ('{"host":"127.0.0.1","port":true}', None),
        ('{"host":"127.0.0.1","port":0}', None),
        ('{"host":"localhost","port":4781}', "http://localhost:4781/v1/hooks/grok"),
        ('{"host":"::1","port":4781}', "http://[::1]:4781/v1/hooks/grok"),
    ],
)
def test_daemon_endpoint_accepts_only_valid_loopback_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str | None,
    expected: str | None,
) -> None:
    monkeypatch.setattr(daemon, "read_private_regular_text", lambda *_args, **_kwargs: state)
    assert daemon._daemon_hook_endpoint(tmp_path, "grok") == expected


def test_ipv6_daemon_endpoint_is_parseable_and_accepted_by_transport() -> None:
    endpoint = "http://[::1]:4781/v1/hooks/grok"
    parsed = urlparse(endpoint)
    assert (parsed.hostname, parsed.port) == ("::1", 4781)
    daemon._assert_loopback_http_url(endpoint)

    response = _Response(body=b'{"policy_action":"allow"}', final_url=endpoint)
    result = daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness="grok",
        input_text='{"hook_event_name":"PreToolUse"}',
        timeout_seconds=2,
        _endpoint_loader=lambda *_args: endpoint,
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(urllib.request.OpenerDirector, _Opener(response)),
    )

    assert result is not None
    stdout, stderr, code = result
    assert json.loads(stdout)["decision"] == "allow"
    assert (stderr, code) == ("", 0)


class _Response:
    def __init__(self, *, body: bytes, status: int = 200, final_url: str = "") -> None:
        self.body = body
        self.status = status
        self.final_url = final_url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.final_url

    def read(self, _limit: int) -> bytes:
        return self.body


class _Opener:
    def __init__(self, outcome: _Response | Exception) -> None:
        self.outcome = outcome

    def open(self, _request: object, *, timeout: float) -> _Response:
        assert 0 < timeout <= daemon._DAEMON_TIMEOUT_BUDGET_SECONDS
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def _try_with(outcome: _Response | Exception) -> tuple[str, str, int] | None:
    return daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness="grok",
        input_text='{"hook_event_name":"PreToolUse"}',
        timeout_seconds=20,
        _endpoint_loader=lambda *_args: "http://127.0.0.1:4781/v1/hooks/grok",
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(urllib.request.OpenerDirector, _Opener(outcome)),
    )


@pytest.mark.parametrize(
    "outcome",
    [
        _Response(body=b"{}", status=503),
        _Response(body=b"{}", final_url="http://example.com/redirect"),
        _Response(body=b"x" * (daemon._MAX_HOOK_RESPONSE_BYTES + 1)),
        _Response(body=b"\xff"),
        _Response(body=b"   "),
        _Response(body=b"not-json"),
        _Response(body=b"[]"),
        urllib.error.URLError("offline"),
        TimeoutError("slow"),
    ],
)
def test_daemon_transport_rejects_invalid_or_untrusted_responses(outcome: _Response | Exception) -> None:
    assert _try_with(outcome) is None


def test_daemon_transport_requires_endpoint_and_token() -> None:
    common = {
        "guard_home": Path("/private/unused"),
        "harness": "grok",
        "input_text": "{}",
        "timeout_seconds": 2,
    }
    assert daemon.try_daemon_hook(**common, _endpoint_loader=lambda *_args: None) is None
    assert (
        daemon.try_daemon_hook(
            **common,
            _endpoint_loader=lambda *_args: "http://example.com/hook",
            _token_loader=lambda _path: "token",
        )
        is None
    )
    assert (
        daemon.try_daemon_hook(
            **common,
            _endpoint_loader=lambda *_args: "http://127.0.0.1:4781/hook",
            _token_loader=lambda _path: None,
        )
        is None
    )


def test_hermes_daemon_response_uses_harness_native_translation(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.adapters import hermes_runtime_hooks

    expected = ('{"decision":"allow"}', "", 0)
    monkeypatch.setattr(hermes_runtime_hooks, "hermes_bridge_response", lambda *_args, **_kwargs: expected)
    result = daemon.try_daemon_hook(
        guard_home=Path("/private/unused"),
        harness="hermes",
        input_text='{"hook_event_name":"PreToolUse"}',
        timeout_seconds=2,
        _endpoint_loader=lambda *_args: "http://127.0.0.1:4781/v1/hooks/hermes",
        _token_loader=lambda _path: "token",
        _opener_builder=lambda: cast(urllib.request.OpenerDirector, _Opener(_Response(body=b'{"x":1}'))),
    )
    assert result == expected


def test_native_response_edge_contracts() -> None:
    assert daemon._native_hook_permission_decision("unknown") is None
    assert daemon._should_exit_block("copilot", "PreToolUse", "block") is False

    stdout, stderr, code = daemon._daemon_response_to_native(
        {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": "blocked",
            }
        },
        harness="kimi",
        event_name="PreToolUse",
    )
    assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert (stderr, code) == ("blocked", 2)

    stdout, _stderr, code = daemon._daemon_response_to_native(
        {"policy_action": "allow"},
        harness="codex",
        event_name="UserPromptSubmit",
    )
    assert json.loads(stdout) == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
    assert code == 0

    stdout, _stderr, code = daemon._daemon_response_to_native(
        {"policy_action": "block", "reason": "blocked"},
        harness="codex",
        event_name="UserPromptSubmit",
    )
    assert json.loads(stdout)["continue"] is False
    assert code == 0


def test_grok_wait_ignores_malformed_native_output(tmp_path: Path) -> None:
    original = ("not-json", "stderr", 2)
    assert (
        daemon._apply_grok_bridge_approval_wait(
            guard_home=tmp_path,
            harness="grok",
            input_text='{"hook_event_name":"PreToolUse"}',
            stdout=original[0],
            stderr=original[1],
            exit_code=original[2],
        )
        == original
    )


def test_bridge_compatibility_wrappers_delegate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    opener = cast(urllib.request.OpenerDirector, object())
    monkeypatch.setattr(daemon, "_daemon_hook_endpoint", lambda home, harness: f"{home}/{harness}")
    monkeypatch.setattr(daemon, "_read_daemon_auth_token", lambda home: home.name)
    monkeypatch.setattr(daemon, "_build_loopback_opener", lambda: opener)
    monkeypatch.setattr(
        daemon,
        "_daemon_response_to_native",
        lambda response, **kwargs: (json.dumps(response), str(kwargs["harness"]), 7),
    )

    assert bridge._daemon_hook_endpoint(tmp_path, "grok") == f"{tmp_path}/grok"
    assert bridge._read_daemon_auth_token(tmp_path) == tmp_path.name
    assert bridge._build_loopback_opener() is opener
    assert bridge._daemon_response_to_native({"x": 1}, harness="grok", event_name="PreToolUse") == (
        '{"x": 1}',
        "grok",
        7,
    )

    captured: dict[str, object] = {}

    def try_hook(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(daemon, "try_daemon_hook", try_hook)
    assert bridge._try_daemon_hook(guard_home=tmp_path, harness="grok", input_text="{}", timeout_seconds=3) is None
    assert captured["_endpoint_loader"] is bridge._daemon_hook_endpoint
    assert captured["_token_loader"] is bridge._read_daemon_auth_token
    assert captured["_opener_builder"] is bridge._build_loopback_opener
